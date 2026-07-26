// sentinel.bpf.c — Sentinel-CC eBPF Enforcer
// Multi-syscall enforcement with audit ring buffer, Deep CFI, and fork tracking
// Hooks: write, read, openat, execve, mmap, mprotect, connect, ptrace,
//        memfd_create, process_vm_writev, prctl, sendmsg, dup2, close,
//        ioctl, seccomp
// Fork tracking: sched_process_fork auto-enrolls child processes
//
// Performance design: the ALLOW (hot) path does zero tracing/audit.
// Only security events (BLOCK, NR_MISMATCH, CFI_FAIL) emit audit +
// bpf_printk. The loader sets `audit_mode` to 1 when --audit is used,
// which enables ALLOW-path auditing for debugging.

#include "../../vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Shared constants and struct layouts (single source of truth).
// clang -target bpf predefines __BPF__, so the header automatically
// selects kernel u8/u32/u64 types — no manual #define needed.
#include "../common/sentinel_shared.h"

// --- Global config (set by loader) ---
volatile const __u32 audit_mode = 0; // 0 = fast path, 1 = verbose audit
volatile const __u32 fexit_mode = 0; // 0 = disabled, 1 = post-syscall audit
volatile const __u32 enforce_mode = 0; // 0 = KILL, 1 = PERMISSIVE, 2 = TERM
volatile const __u32 learn_mode = 0;   // 0 = enforce, 1 = learning (record all)
volatile const __u32 shadow_cfi = 0;   // 0 = disabled, 1 = shadow stack CFI
volatile const __u32 system_wide = 0;  // 0 = per-binary, 1 = all processes

// --- Maps ---

// 1. Inner Map Template (Policy for a specific module)
struct inner_policy_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u64);   // Offset (RIP - Base)
  __type(value, u64); // 1 = allowed
} inner_policy SEC(".maps");

// 2. Policy Registry (Array of Maps — one per module)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, 64);
  __type(key, u32);
  __type(value, u32);
} policy_registry SEC(".maps");

// 3. VMA Trie (Longest Prefix Match for address→module resolution)
// Uses struct vma_key / vma_value from sentinel_shared.h
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 512);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct vma_key);
  __type(value, struct vma_value);
} vma_map SEC(".maps");

// 4. PID Tracking (TGID → 1)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, u32);
  __type(value, u32);
} target_pid_map SEC(".maps");

// 5. Deep CFI Policy Map
// Maps Syscall_Offset → {Caller_Start_Offset, Caller_End_Offset}
// Uses struct cfi_range from sentinel_shared.h
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, struct cfi_range);
} cfi_policy SEC(".maps");

// 6. Audit Ring Buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); // 256KB
} audit_ringbuf SEC(".maps");

// 7. Cgroup Tracking (cgroup_id → 1)
// When populated, only processes in these cgroups are enforced.
// Empty map = enforce all monitored PIDs (default, backward compatible).
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, u64);   // cgroup ID (from bpf_get_current_cgroup_id())
  __type(value, u32); // 1 = enforce
} cgroup_map SEC(".maps");

// 8. Per-Thread Policy Override map removed

// 9. Learning Mode Map — records observed {offset → (mod_id << 32)|syscall_nr}
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, u64);
  __type(value, u64);
} learn_map SEC(".maps");

// 10. System-Wide Fallback Policy (NR → allowed)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 512);
  __type(key, u32);
  __type(value, u32);
} fallback_policy SEC(".maps");

// 11. Allowed Library Hashes (FNV-1a hash of path → 1)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, u64);
  __type(value, u32);
} lib_allow_map SEC(".maps");

// Global: 0 = cgroup filtering disabled, 1 = only enforce in listed cgroups
volatile const __u32 cgroup_filter = 0;

// --- Helpers ---

static __always_inline void emit_audit(u32 tgid, u32 tid, u64 rip,
                                       u64 offset, u32 mod_id,
                                       u32 syscall_nr, u8 action) {
  struct audit_event *evt;
  evt = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*evt), 0);
  if (!evt)
    return;
  evt->timestamp_ns = bpf_ktime_get_ns();
  evt->tgid = tgid;
  evt->tid = tid;
  evt->syscall_rip = rip;
  evt->offset = offset;
  evt->module_id = mod_id;
  evt->syscall_nr = syscall_nr;
  evt->action = action;
  bpf_ringbuf_submit(evt, 0);
}

// Deny action: kill, log-only (permissive), or terminate
static __always_inline void deny_action(u32 tgid, u32 tid, u64 rip,
                                        u64 offset, u32 mod_id,
                                        u32 syscall_nr, u8 event_type) {
  emit_audit(tgid, tid, rip, offset, mod_id, syscall_nr, event_type);
  if (enforce_mode == ENFORCE_TERM)
    bpf_send_signal(15); // SIGTERM
  else if (enforce_mode == ENFORCE_KILL)
    bpf_send_signal(9);  // SIGKILL
}

// Core enforcement logic — shared by all syscall hooks
// Hot path (ALLOW) is minimal: 3 map lookups + 1 compare, zero I/O.
static __always_inline int sentinel_check(void *ctx, u32 syscall_nr) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;

  // System-wide mode: enforce for ALL processes (fallback for unsigned)
  // Per-binary mode: only enforce for tracked TGIDs
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &tgid);
  if (!target) {
    if (!system_wide)
      return 0;
    // System-wide fallback: check NR against generic allow-list
    u32 *fallback_ok = bpf_map_lookup_elem(&fallback_policy, &syscall_nr);
    if (fallback_ok)
      return 0; // Syscall allowed by fallback policy
    u32 tid = (u32)pid_tgid;
    deny_action(tgid, tid, 0, 0, 0, syscall_nr, EVENT_BLOCK);
    return 0;
  }

  // Container/cgroup scoping: if cgroup_filter is enabled,
  // skip enforcement for processes outside the allowed cgroups
  if (cgroup_filter) {
    u64 cgid = bpf_get_current_cgroup_id();
    u32 *cg_allowed = bpf_map_lookup_elem(&cgroup_map, &cgid);
    if (!cg_allowed)
      return 0; // Not in an enforced cgroup — skip
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
  if (!regs) {
    u32 tid = (u32)pid_tgid;
    bpf_printk("Sentinel [BLOCK] TID=%d SYS=%d null pt_regs", tid, syscall_nr);
    deny_action(tgid, tid, 0, 0, 0, syscall_nr, EVENT_BLOCK);
    return 0;
  }

  u32 tid = (u32)pid_tgid;

  // 1. Get Syscall RIP ('syscall' is 2 bytes: 0x0f 0x05)
  u64 rip = PT_REGS_IP_CORE(regs);
  u64 syscall_site = rip - 2;

  // 2. Lookup Module via LPM Trie (Big-Endian key for prefix matching)
  struct vma_key vkey = {.prefixlen = 64,
                         .addr = __builtin_bswap64(syscall_site)};
  struct vma_value *mod = bpf_map_lookup_elem(&vma_map, &vkey);

  if (!mod) {
    bpf_printk("Sentinel [BLOCK] TID=%d SYS=%d Unknown VMA 0x%lx", tid,
               syscall_nr, syscall_site);
    deny_action(tgid, tid, syscall_site, 0, 0, syscall_nr, EVENT_BLOCK);
    return 0;
  }

  // 3. Normalize to module-relative offset
  u64 offset = syscall_site - mod->base_addr;

  // 4. Policy Check via Map-of-Maps
  void *policy_map = bpf_map_lookup_elem(&policy_registry, &mod->module_id);
  if (!policy_map) {
    bpf_printk("Sentinel [BLOCK] TID=%d SYS=%d No Policy Mod=%d", tid,
               syscall_nr, mod->module_id);
    deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
               EVENT_BLOCK);
    return 0;
  }

  u64 *rule = bpf_map_lookup_elem(policy_map, &offset);
  if (!rule) {
    bpf_printk("Sentinel [BLOCK] TID=%d SYS=%d Vio Offset 0x%lx",
               tid, syscall_nr, offset);
    deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
               EVENT_BLOCK);
    return 0;
  }

  // 5. Validate Syscall Number matches policy expectations
  u64 policy_val = *rule;
  if (policy_val & POLICY_FLAG_CHECK_NR) {
    u32 expected_nr = (u32)(policy_val & 0xFFFFFFFF);
    if (expected_nr != syscall_nr) {
      bpf_printk("Sentinel [NR-MISMATCH] TID=%d Got %d Off 0x%lx",
                 tid, syscall_nr, offset);
      deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
                  EVENT_NR_MISMATCH);
      return 0;
    }
  }

  // 6. Deep CFI: Caller Validation (optional, per-site)
  struct cfi_range *range = bpf_map_lookup_elem(&cfi_policy, &offset);
  if (range) {
    u64 stack[4] = {0}; // [0]=current IP, [1]=caller IP
    long ret = bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);

    if (ret >= 16) { // At least 2 frames (8 bytes each)
      u64 caller_rip = stack[1];
      u64 caller_offset = caller_rip - mod->base_addr;

      if (caller_offset >= range->start && caller_offset <= range->end) {
        if (audit_mode) {
          emit_audit(tgid, tid, syscall_site, offset, mod->module_id,
                     syscall_nr, EVENT_CFI_OK);
        }
        return 0;
      } else {
        bpf_printk(
            "Sentinel [CFI-FAIL] TID=%d BadCaller 0x%lx",
            tid, caller_offset);
        deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
                    EVENT_CFI_FAIL);
        return 0;
      }
    }
    bpf_printk("Sentinel [CFI-FAIL] TID=%d SYS=%d stack walk failed (ret=%ld)",
               tid, syscall_nr, ret);
    deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
                EVENT_CFI_FAIL);
    return 0;
  }

  // --- ALLOW: fast path — zero tracing overhead ---
  // Audit-mode only: emit allow events for debugging/profiling.
  if (audit_mode) {
    emit_audit(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
               EVENT_ALLOW);
  }
  return 0;
}

// --- Per-Syscall fentry Hooks ---

SEC("fentry/__x64_sys_write")
int BPF_PROG(sentinel_write_check) {
  return sentinel_check(ctx, 1);
}

SEC("fentry/__x64_sys_read")
int BPF_PROG(sentinel_read_check) {
  return sentinel_check(ctx, 0);
}

SEC("fentry/__x64_sys_openat")
int BPF_PROG(sentinel_openat_check) {
  return sentinel_check(ctx, 257);
}

SEC("fentry/__x64_sys_execve")
int BPF_PROG(sentinel_execve_check) {
  return sentinel_check(ctx, 59);
}

SEC("fentry/__x64_sys_mmap")
int BPF_PROG(sentinel_mmap_check) {
  return sentinel_check(ctx, 9);
}

SEC("fentry/__x64_sys_mprotect")
int BPF_PROG(sentinel_mprotect_check) {
  return sentinel_check(ctx, 10);
}

SEC("fentry/__x64_sys_connect")
int BPF_PROG(sentinel_connect_check) {
  return sentinel_check(ctx, 42);
}

// --- Additional high-risk syscall hooks ---

SEC("fentry/__x64_sys_memfd_create")
int BPF_PROG(sentinel_memfd_create_check) {
  return sentinel_check(ctx, 319);
}

SEC("fentry/__x64_sys_process_vm_writev")
int BPF_PROG(sentinel_process_vm_writev_check) {
  // process_vm_writev allows cross-process memory writes — extremely dangerous.
  // Unconditionally block for monitored processes (same rationale as ptrace).
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &tgid);
  if (!target)
    return 0;
  u32 tid = (u32)pid_tgid;
  bpf_printk("Sentinel [BLOCK] TID=%d process_vm_writev denied", tid);
  deny_action(tgid, tid, 0, 0, 0, 311, EVENT_BLOCK);
  return 0;
}

SEC("fentry/__x64_sys_prctl")
int BPF_PROG(sentinel_prctl_check) {
  return sentinel_check(ctx, 157);
}

SEC("fentry/__x64_sys_sendmsg")
int BPF_PROG(sentinel_sendmsg_check) {
  return sentinel_check(ctx, 46);
}

SEC("fentry/__x64_sys_dup2")
int BPF_PROG(sentinel_dup2_check) {
  return sentinel_check(ctx, 33);
}

SEC("fentry/__x64_sys_close")
int BPF_PROG(sentinel_close_check) {
  return sentinel_check(ctx, 3);
}

SEC("fentry/__x64_sys_ioctl")
int BPF_PROG(sentinel_ioctl_check) {
  return sentinel_check(ctx, 16);
}

SEC("fentry/__x64_sys_seccomp")
int BPF_PROG(sentinel_seccomp_check) {
  // seccomp is unconditionally blocked for monitored processes.
  // An attacker could use seccomp to install filters that interfere
  // with Sentinel's enforcement or to disable signal delivery.
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &tgid);
  if (!target)
    return 0;
  u32 tid = (u32)pid_tgid;
  bpf_printk("Sentinel [BLOCK] TID=%d seccomp denied for monitored process", tid);
  deny_action(tgid, tid, 0, 0, 0, 317, EVENT_BLOCK);
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
