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
#define SENTINEL_VERSION "4.1.0"

// --- Module IDs ---
#define MODULE_MAIN         1
#define MODULE_LIBC         2
#define MODULE_DYNAMIC_BASE 3  // First dynamically-assigned module ID

// --- Audit Event Constants ---
#define EVENT_ALLOW       0
#define EVENT_BLOCK       1
#define EVENT_CFI_OK      2
#define EVENT_CFI_FAIL    3
#define EVENT_NR_MISMATCH 4
#define EVENT_FORK_TRACK  5  // Child auto-enrolled via sched_process_fork

// --- Phase 3: Policy value encoding ---
// Bit 32 = validate syscall number; bits 0-31 = expected syscall number
// If bit 32 is clear, policy value == 1 means "wildcard — allow any nr"
#define POLICY_FLAG_CHECK_NR (1ULL << 32)

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
#endif

#endif // SENTINEL_SHARED_H
