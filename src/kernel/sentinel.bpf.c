// sentinel.bpf.c
// Sentinel-CC Phase 3 — Context-Sensitive Enforcement (CFI)
// Enforces that syscalls are not only at allowed locations (Offsets),
// but also originate from allowed CALLERS (Stack Check).

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Phase 3: Policy Rule now includes Caller Range
struct policy_rule {
  u64 allowed_caller_start;
  u64 allowed_caller_end;
};

// Map: Target PID
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32);
} target_pid_map SEC(".maps");

// Map: Policy (Syscall Offset -> Allowed Caller Range)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);                  // Syscall Instruction Offset
  __type(value, struct policy_rule); // Requirement for Caller
} policy_map SEC(".maps");

SEC("fentry/__x64_sys_write")
int BPF_PROG(sentinel_write_check) {
  // 0. PID Filter
  u32 key0 = 0;
  u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key0);
  if (!target_pid || *target_pid == 0)
    return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (pid != *target_pid)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
  if (!regs)
    return 0;

  // 1. IP Check (Base Enforcement)
  unsigned long ip = PT_REGS_IP_CORE(regs);
  unsigned long start_code = BPF_CORE_READ(task, mm, start_code);
  unsigned long offset = ip - start_code;

  struct policy_rule *rule = bpf_map_lookup_elem(&policy_map, &offset);
  if (!rule) {
    // Unknown Syscall Location -> BLOCK
    bpf_printk("Sentinel BLOCK: PID=%d SyscallInvalid 0x%lx", pid, offset);
    bpf_send_signal(9);
    return 0;
  }

  // 2. Stack Verification (Phase 3)
  // Who called this function?
  // We retrieve the user stack to find the Return Address.
  // stack[0] = IP (Next instruction after syscall, same as offset).
  // stack[1] = Caller (Return Address).
  u64 stack[4];
  long ret = bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);

  if (ret < 0) {
    // Failed to walk stack -> Fail Secure
    bpf_printk("Sentinel BLOCK: PID=%d StackWalkFail", pid);
    bpf_send_signal(9);
    return 0;
  }

  // Normalize Caller IP to Offset
  u64 caller_ip = stack[1];
  u64 caller_offset = caller_ip - start_code;

  // 3. CFI Check
  if (caller_offset >= rule->allowed_caller_start &&
      caller_offset <= rule->allowed_caller_end) {

    bpf_printk("Sentinel ALLOW: PID=%d Syscall 0x%lx Caller 0x%lx (Valid)", pid,
               offset, caller_offset);
    return 0;
  }

  // 4. Violation Detected! (Valid Gadget, Invalid Caller)
  bpf_printk("Sentinel BLOCK: PID=%d Syscall 0x%lx Caller 0x%lx (INVALID)", pid,
             offset, caller_offset);
  bpf_send_signal(9);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";