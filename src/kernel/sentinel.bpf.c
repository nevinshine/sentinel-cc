#include "../../vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// --- Phase 2 & 3: Map-of-Maps + Deep CFI ---

// 1. Inner Map Template (The Policy for a specific library)
struct inner_policy_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);   // Offset (RIP - Base)
  __type(value, u64); // Allowed Caller Start (Simplified for now)
} inner_policy SEC(".maps");

// 2. Policy Registry (Array of Maps)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, 64);
  __type(key, u32);
  __array(values, struct inner_policy_map);
} policy_registry SEC(".maps");

// 3. VMA Trie (Longest Prefix Match)
struct vma_key {
  u32 prefixlen;
  u64 addr;
};

struct vma_value {
  u32 module_id;
  u64 base_addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct vma_key);
  __type(value, struct vma_value);
} vma_map SEC(".maps");

// 4. PID Tracking
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16);
  __type(key, u32);
  __type(value, u32);
} target_pid_map SEC(".maps");

// 5. Deep CFI Policy Map (Phase 2.2)
// Maps Syscall_Offset -> {Caller_Start_Offset, Caller_End_Offset}
struct cfi_range {
  u64 start;
  u64 end;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, u64);
  __type(value, struct cfi_range);
} cfi_policy SEC(".maps");

SEC("fentry/__x64_sys_write")
int BPF_PROG(sentinel_write_check) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  // Check if TGID is monitored (covers all threads)
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &tgid);
  if (!target)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
  if (!regs)
    return 0;

  // 1. Get Syscall RIP
  u64 rip = PT_REGS_IP_CORE(regs);
  u64 syscall_site = rip - 2;

  // 2. Lookup Module
  // FIX: Use __builtin_bswap64 to match Big Endian keys in LPM Trie
  struct vma_key vkey = {.prefixlen = 64, .addr = __builtin_bswap64(syscall_site)};
  struct vma_value *mod = bpf_map_lookup_elem(&vma_map, &vkey);

  if (!mod) {
    bpf_printk("Sentinel [BLOCK] TID=%d Unknown VMA 0x%lx", tid, syscall_site);
    bpf_send_signal(9);
    return 0;
  }

  // 3. Normalize Address
  u64 offset = syscall_site - mod->base_addr;

  // 4. Policy Check
  void *policy_map = bpf_map_lookup_elem(&policy_registry, &mod->module_id);
  if (!policy_map) {
    bpf_printk("Sentinel [BLOCK] TID=%d No Policy Mod=%d", tid, mod->module_id);
    bpf_send_signal(9);
    return 0;
  }

  u64 *rule = bpf_map_lookup_elem(policy_map, &offset);
  if (!rule) {
    bpf_printk("Sentinel [BLOCK] TID=%d Vio Offset 0x%lx (Mod %d)", tid, offset,
               mod->module_id);
    bpf_send_signal(9);
    return 0;
  }

  // --- Phase 2.2: Deep CFI (Caller Validation) ---
  struct cfi_range *range = bpf_map_lookup_elem(&cfi_policy, &offset);
  if (range) {
    // Walk the stack to find the caller
    u64 stack[4]; // [0]=IP(in do_write), [1]=IP(caller)
    long ret = bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);

    if (ret >= 16) { // Need at least 2 frames (8 bytes each)
      u64 caller_rip = stack[1];
      // Assumption: Caller is in same module for this test
      u64 caller_offset = caller_rip - mod->base_addr;

      if (caller_offset >= range->start && caller_offset <= range->end) {
        bpf_printk("Sentinel [ALLOW+CFI] TID=%d Call 0x%lx -> Sys 0x%lx", tid,
                   caller_offset, offset);
        return 0;
      } else {
        bpf_printk(
            "Sentinel [CFI-FAIL] TID=%d BadCaller 0x%lx (Valid: 0x%lx-0x%lx)",
            tid, caller_offset, range->start, range->end);
        bpf_send_signal(9);
        return 0;
      }
    }
  }

  bpf_printk("Sentinel [ALLOW] TID=%d Mod %d Off 0x%lx", tid, mod->module_id,
             offset);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";