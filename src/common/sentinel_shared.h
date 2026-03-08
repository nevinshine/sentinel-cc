// sentinel_shared.h — Shared type definitions between BPF and userspace
//
// This header is the single source of truth for all data structures and
// constants exchanged between sentinel.bpf.c and loader.c. Both sides
// include this file to prevent silent struct divergence.
//
// BPF side:  uses kernel u8/u32/u64 types
// User side: uses stdint uint8_t/uint32_t/uint64_t types
// We use preprocessor to bridge the type gap.

#ifndef SENTINEL_SHARED_H
#define SENTINEL_SHARED_H

// --- Type bridging ---
// BPF programs define __BPF__ or include vmlinux.h which provides u8/u32/u64.
// Userspace needs stdint equivalents.
#ifdef __BPF__
  // BPF side: kernel types already available (u8, u32, u64)
  #define S_U8  u8
  #define S_U32 u32
  #define S_U64 u64
#else
  #include <stdint.h>
  #define S_U8  uint8_t
  #define S_U32 uint32_t
  #define S_U64 uint64_t
#endif

// --- Version ---
#define SENTINEL_VERSION "4.5.0"

// --- Module IDs ---
#define MODULE_MAIN         1
#define MODULE_LIBC         2
#define MODULE_DYNAMIC_BASE 3  // First dynamically-assigned module ID

// --- Enforcement Mode ---
#define ENFORCE_KILL       0  // SIGKILL on violation (default, fail-closed)
#define ENFORCE_PERMISSIVE 1  // Log violation but do not kill (audit-only)
#define ENFORCE_TERM       2  // SIGTERM on violation (graceful shutdown)

// --- Audit Event Constants ---
#define EVENT_ALLOW       0
#define EVENT_BLOCK       1
#define EVENT_CFI_OK      2
#define EVENT_CFI_FAIL    3
#define EVENT_NR_MISMATCH 4
#define EVENT_FORK_TRACK  5  // Child auto-enrolled via sched_process_fork
#define EVENT_FEXIT_OK    6  // Post-syscall return audit (fexit)
#define EVENT_DLOPEN_EXT  7  // Runtime dlopen() policy extension
#define EVENT_PERMISSIVE  8  // Violation logged in permissive mode (not killed)
#define EVENT_LEARN       9  // Learning mode: observed syscall recorded
#define EVENT_LIB_DENY   10  // Unauthorized library load denied
#define EVENT_SHADOW_OK  11  // Shadow stack validation passed
#define EVENT_SHADOW_FAIL 12 // Shadow stack validation failed
#define EVENT_FALLBACK   13  // System-wide fallback policy applied
#define EVENT_KOBJ_DENY  14  // Kernel object manipulation denied (bpf/unshare/setns)

// --- Max constants ---
#define MAX_SHADOW_DEPTH 8  // Max stack frames for shadow stack CFI
// --- Phase 3: Policy value encoding ---
// Bit 32 = validate syscall number; bits 0-31 = expected syscall number
// If bit 32 is clear, policy value == 1 means "wildcard — allow any nr"
#define POLICY_FLAG_CHECK_NR (1ULL << 32)

// --- Policy Format Version ---
// Magic bytes + version at the start of .sentinel section
#define SENTINEL_POLICY_MAGIC   0x53454E54U  // "SENT"
#define SENTINEL_POLICY_VERSION 2            // Format version (v2 adds NR binding)

// --- Audit Event Structure ---
// Transmitted via BPF ring buffer from kernel to userspace.
// Layout must be identical on both sides.
struct audit_event {
  S_U64 timestamp_ns;
  S_U32 tgid;
  S_U32 tid;
  S_U64 syscall_rip;
  S_U64 offset;
  S_U32 module_id;
  S_U32 syscall_nr;
  S_U8  action;
  S_U8  _pad[7];
};

// --- VMA LPM Trie Types ---
// Packed to match BPF map layout (no padding between u32 and u64)
struct vma_key {
  S_U32 prefixlen;
  S_U64 addr;
} __attribute__((packed));

struct vma_value {
  S_U32 module_id;
  S_U64 base_addr;
} __attribute__((packed));

// --- Deep CFI Range ---
struct cfi_range {
  S_U64 start;
  S_U64 end;
};

// --- Thread Policy Key (for per-thread enforcement) ---
struct thread_key {
  S_U32 tgid;
  S_U32 tid;
};

// --- Kernel Subsystem Mapping ---
// Maps syscall numbers to kernel subsystem categories for attack surface reports
#define SUBSYS_PROCESS   0  // fork, execve, exit, prctl
#define SUBSYS_FILESYSTEM 1 // open, read, write, close, stat
#define SUBSYS_NETWORK   2  // connect, sendmsg, socket, bind
#define SUBSYS_MEMORY    3  // mmap, mprotect, brk
#define SUBSYS_IPC       4  // pipe, shmget, msgget
#define SUBSYS_SIGNAL    5  // kill, sigaction
#define SUBSYS_DEVICE    6  // ioctl, read/write on devices
#define SUBSYS_SECURITY  7  // seccomp, ptrace, keyctl
#define SUBSYS_OTHER     8

// --- Compile-time struct size assertions ---
// These catch layout divergence at build time rather than at runtime.
#ifndef __BPF__
_Static_assert(sizeof(struct audit_event) == 48,
               "audit_event size mismatch — update both BPF and loader");
_Static_assert(sizeof(struct vma_key) == 12,
               "vma_key size mismatch");
_Static_assert(sizeof(struct vma_value) == 12,
               "vma_value size mismatch — check padding");
_Static_assert(sizeof(struct cfi_range) == 16,
               "cfi_range size mismatch");
_Static_assert(sizeof(struct thread_key) == 8,
               "thread_key size mismatch");
#endif

#endif // SENTINEL_SHARED_H
