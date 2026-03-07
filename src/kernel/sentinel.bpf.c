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
  __array(values, struct inner_policy_map);
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
  if (enforce_mode == ENFORCE_PERMISSIVE) {
    // Permissive mode: log the violation but do NOT kill
    emit_audit(tgid, tid, rip, offset, mod_id, syscall_nr, EVENT_PERMISSIVE);
    bpf_printk("Sentinel [PERMISSIVE] TID=%d SYS=%d Off=0x%lx (would BLOCK)",
               tid, syscall_nr, offset);
    return;
  }
  emit_audit(tgid, tid, rip, offset, mod_id, syscall_nr, event_type);
  if (enforce_mode == ENFORCE_TERM)
    bpf_send_signal(15); // SIGTERM — graceful
  else
    bpf_send_signal(9);  // SIGKILL — fail-closed default
}

// Core enforcement logic — shared by all syscall hooks
// Hot path (ALLOW) is minimal: 3 map lookups + 1 compare, zero I/O.
static __always_inline int sentinel_check(void *ctx, u32 syscall_nr) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;

  // Check if TGID is monitored (covers all threads in the process)
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &tgid);
  if (!target)
    return 0;

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
    // pt_regs unavailable — cannot validate syscall origin.
    // BLOCK instead of silently allowing: fail-closed.
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
    bpf_printk("Sentinel [BLOCK] TID=%d SYS=%d Vio Offset 0x%lx (Mod %d)",
               tid, syscall_nr, offset, mod->module_id);
    deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
               EVENT_BLOCK);
    return 0;
  }

  // 5. Phase 3: Syscall Number Validation
  u64 policy_val = *rule;
  if (policy_val & POLICY_FLAG_CHECK_NR) {
    u32 expected_nr = (u32)(policy_val & 0xFFFFFFFF);
    if (expected_nr != syscall_nr) {
      bpf_printk("Sentinel [NR-MISMATCH] TID=%d Got %d Want %d Off 0x%lx",
                 tid, syscall_nr, expected_nr, offset);
      deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
                  EVENT_NR_MISMATCH);
      return 0;
    }
  }

  // 6. Deep CFI: Caller Validation (optional, per-site)
  struct cfi_range *range = bpf_map_lookup_elem(&cfi_policy, &offset);
  if (range) {
    u64 stack[4]; // [0]=current IP, [1]=caller IP
    long ret = bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);

    if (ret >= 16) { // At least 2 frames (8 bytes each)
      u64 caller_rip = stack[1];
      u64 caller_offset = caller_rip - mod->base_addr;

      if (caller_offset >= range->start && caller_offset <= range->end) {
        // CFI passed — fall through to allow
        if (audit_mode) {
          emit_audit(tgid, tid, syscall_site, offset, mod->module_id,
                     syscall_nr, EVENT_CFI_OK);
        }
        return 0;
      } else {
        bpf_printk(
            "Sentinel [CFI-FAIL] TID=%d BadCaller 0x%lx (Valid: 0x%lx-0x%lx)",
            tid, caller_offset, range->start, range->end);
        deny_action(tgid, tid, syscall_site, offset, mod->module_id, syscall_nr,
                    EVENT_CFI_FAIL);
        return 0;
      }
    }
    // Stack walk failed — BLOCK instead of silently allowing.
    // If we can't verify the caller, assume compromise.
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

SEC("fentry/__x64_sys_ptrace")
int BPF_PROG(sentinel_ptrace_check) {
  // Ptrace from a monitored process is unconditionally blocked.
  // A Sentinel-protected binary should never debug/inject other processes.
  // Without this, ptrace goes through libc which is fully whitelisted.
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &tgid);
  if (!target)
    return 0;
  u32 tid = (u32)pid_tgid;
  bpf_printk("Sentinel [BLOCK] TID=%d ptrace denied for monitored process", tid);
  deny_action(tgid, tid, 0, 0, 0, 101, EVENT_BLOCK);
  return 0;
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

// --- Fork Tracking ---
// Automatically enroll child processes when a monitored parent forks/clones.
// This prevents fork-and-escape attacks where a child runs unmonitored.

// --- fexit Hooks: Post-Syscall Audit ---
// When fexit_mode is enabled, these hooks emit the syscall return value
// after the kernel completes the syscall. Useful for observability: see
// which syscalls succeed/fail without affecting enforcement.

static __always_inline void fexit_audit(u32 syscall_nr, long ret) {
  if (!fexit_mode)
    return;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &tgid);
  if (!target)
    return;
  u32 tid = (u32)pid_tgid;
  // Encode return value in the offset field for compact transport
  emit_audit(tgid, tid, 0, (u64)ret, 0, syscall_nr, EVENT_FEXIT_OK);
}

SEC("fexit/__x64_sys_write")
int BPF_PROG(sentinel_write_exit, struct pt_regs *regs, long ret) {
  fexit_audit(1, ret);
  return 0;
}

SEC("fexit/__x64_sys_read")
int BPF_PROG(sentinel_read_exit, struct pt_regs *regs, long ret) {
  fexit_audit(0, ret);
  return 0;
}

SEC("fexit/__x64_sys_openat")
int BPF_PROG(sentinel_openat_exit, struct pt_regs *regs, long ret) {
  fexit_audit(257, ret);
  return 0;
}

SEC("fexit/__x64_sys_mmap")
int BPF_PROG(sentinel_mmap_exit, struct pt_regs *regs, long ret) {
  fexit_audit(9, ret);
  return 0;
}

SEC("fexit/__x64_sys_connect")
int BPF_PROG(sentinel_connect_exit, struct pt_regs *regs, long ret) {
  fexit_audit(42, ret);
  return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sentinel_fork_track, struct task_struct *parent,
             struct task_struct *child) {
  u32 parent_tgid = BPF_CORE_READ(parent, tgid);
  u32 *tracked = bpf_map_lookup_elem(&target_pid_map, &parent_tgid);
  if (!tracked)
    return 0;

  // Parent is monitored — auto-enroll the child
  u32 child_tgid = BPF_CORE_READ(child, tgid);
  u32 val = 1;
  if (bpf_map_update_elem(&target_pid_map, &child_tgid, &val, BPF_ANY) == 0) {
    bpf_printk("Sentinel [FORK] Parent %d -> Child %d auto-enrolled",
               parent_tgid, child_tgid);
    emit_audit(parent_tgid, child_tgid, 0, 0, 0, 0, EVENT_FORK_TRACK);
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";