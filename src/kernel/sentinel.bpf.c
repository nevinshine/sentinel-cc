#include "../../vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// --- Phase 2: Map-of-Maps Architecture ---

// 1. Inner Map Template (The Policy for a specific library)
struct inner_policy_map {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);   // Offset (RIP - Base)
  __type(value, u64); // Allowed Caller Start (Simplified for now)
} inner_policy SEC(".maps");

// 2. Policy Registry (Array of Maps)
// Maps Module_ID -> Inner_Policy_Map
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, 64);
  __type(key, u32);
  __array(values, struct inner_policy_map);
} policy_registry SEC(".maps");

// 3. VMA Trie (Longest Prefix Match)
// Maps RIP -> {Module_ID, Base_Address}
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

SEC("fentry/__x64_sys_write")
int BPF_PROG(sentinel_write_check) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 *target = bpf_map_lookup_elem(&target_pid_map, &pid);
  if (!target)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
  if (!regs)
    return 0;

  // 1. Get Current RIP (ASLR Address)
  u64 rip = PT_REGS_IP_CORE(regs);
  // Syscall instruction is 2 bytes (0x0f 0x05), so the call site is RIP - 2

  // Note: BPF_CORE_READ(regs, rip) gets the instruction pointer *at the time of
  // trap*. For fentry/kprobe, this is usually the start of the function, but
  // for syscall tracepoints it's the return address in userspace (instruction
  // after syscall). The user provided logic subtracts 2. We trust this matches
  u64 syscall_site = rip - 2;

  // 2. Lookup Module in VMA Trie
  struct vma_key vkey = {.prefixlen = 64, .addr = syscall_site};
  struct vma_value *mod = bpf_map_lookup_elem(&vma_map, &vkey);

  if (!mod) {
    bpf_printk("Sentinel BLOCK: PID=%d Unknown VMA region at 0x%lx", pid,
               syscall_site);
    bpf_send_signal(9);
    return 0;
  }

  // 3. Normalize Address (Offset = RIP - Base)
  u64 offset = syscall_site - mod->base_addr;

  // 4. Lookup Policy in Registry
  // We need to find the specific map for this Module ID
  void *policy_map = bpf_map_lookup_elem(&policy_registry, &mod->module_id);
  if (!policy_map) {
    bpf_printk("Sentinel BLOCK: PID=%d No policy for Module %d", pid,
               mod->module_id);
    bpf_send_signal(9);
    return 0;
  }

  // 5. Check Inner Policy
  u64 *rule = bpf_map_lookup_elem(policy_map, &offset);
  if (rule) {
    bpf_printk("Sentinel ALLOW: Module %d Offset 0x%lx (Normalized)",
               mod->module_id, offset);
    return 0;
  }

  bpf_printk("Sentinel BLOCK: Module %d Offset 0x%lx (Violation)",
             mod->module_id, offset);
  bpf_send_signal(9);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";