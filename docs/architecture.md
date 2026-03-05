# Sentinel-CC Architecture

> System architecture deep-dive for Sentinel-CC v4.0.0

## Overview

Sentinel-CC is a **Policy-Carrying Code (PCC)** enforcement system. The compiler embeds security policy directly into the binary, a signer cryptographically binds it, and an eBPF-based kernel enforcer validates every security-sensitive syscall at runtime.

The architecture has four components that form a continuous chain of trust:

```
Source Code ──► LLVM Pass ──► Signed Binary ──► Loader ──► eBPF Enforcer
   (1)           (2)            (3)             (4)          (5)
```

## Component Architecture

### 1. Compiler Pass (`SentinelPass.cpp`)

An LLVM `ModulePass` plugin that runs at compile time via `-fpass-plugin=`.

**Responsibilities:**
- Scan every function for syscall-emitting instructions
- Split basic blocks to create precise labels at each syscall site
- Emit `.sentinel` section (policy array)
- Emit `.sentinel_cfi` section (caller-range metadata)
- Emit `.sentinel_imports` section (external function list)
- Emit `.signature` placeholder (64 bytes for Ed25519)
- Detect obfuscated `.byte 0x0f, 0x05` encodings

**Syscall Detection Pipeline:**

```
Inline ASM ──► String match: "syscall", "int $0x80", "svc #0"
           ──► Obfuscated: .byte 0x0f,0x05 / \x0f\x05 (regex)
           ──► Register analysis: extract RAX value for NR binding

Calls      ──► 50+ known wrapper names (write, mmap, fopen, printf, ...)
           ──► Mapped to x86-64 NR where deterministic
```

**Output Sections:**

| Section | Content | Format |
|---------|---------|--------|
| `.sentinel` | Syscall site whitelist | `{void *site, void *func, int64_t nr}[]` |
| `.sentinel_cfi` | Caller-range pairs | `{void *site, void *func}[]` |
| `.sentinel_imports` | External function names | Null-terminated string blob |
| `.signature` | Ed25519 signature | 64 bytes (placeholder, filled by signer) |

### 2. Signing Tool (`sign_tool.c`)

Signs the binary after compilation. Computes `SHA-256(concatenation of .text + .sentinel + .sentinel_cfi + .sentinel_imports)` and signs the hash with Ed25519.

**Trust Model:**
- Private key (`priv.pem`) held by the build system only
- Public key (`pub.pem`) distributed to runtime environments
- Signature covers code + all policy sections — any tampering invalidates the binding

### 3. Runtime Loader (`loader.c`)

The loader is the largest component (~2050 lines). It bridges the signed binary to the kernel enforcer.

**Execution Flow:**

```
1. Parse CLI flags (--audit, --help, --version)
2. Verify Ed25519 signature via Linux Kernel Keyring
   ├── Read .text, .sentinel, .sentinel_cfi, .sentinel_imports
   ├── Compute SHA-256 hash of concatenated sections
   ├── Fetch public key from session keyring (user:sentinel:pubkey)
   ├── Check key against /etc/sentinel/revoked_keys
   └── EVP_DigestVerifyInit/Final with Ed25519
3. Fork child process (stopped via PTRACE_TRACEME)
4. Load BPF skeleton (sentinel.skel.h)
5. Parse .sentinel → extract offsets + syscall NRs
6. Register TGID in target_pid_map
7. Populate VMA LPM trie from /proc/PID/maps
8. Create inner policy maps (per-module)
   ├── Module 1 (Main binary): offsets from .sentinel
   └── Module 2 (Libc): call-graph filtered offsets
9. Per-app libc filtering (if .sentinel_imports present):
   ├── Parse imports from .sentinel_imports
   ├── Load libc executable sections into memory
   ├── BFS from imported symbols through E8/E9 opcodes
   ├── Whitelist only reachable 0F 05 sites
   └── Report attack surface reduction ratio
10. Setup CFI policy from .sentinel_cfi
11. Resume child (PTRACE_DETACH)
12. Poll audit ring buffer (if --audit)
13. Wait for child exit, cleanup BPF
```

**Call-Graph BFS Algorithm (Per-App Filtering):**

```
Seeds: imported symbols from .sentinel_imports
Queue: BFS work queue
Visited: set of already-processed function names

while queue is not empty:
    func = dequeue()
    scan func body for:
        E8 xx xx xx xx  →  resolve CALL rel32 target → enqueue if new symbol
        E9 xx xx xx xx  →  resolve JMP rel32 target → enqueue if new symbol
        0F 05           →  record as reachable syscall site

Also auto-discovers __* glibc internal variants (e.g., fopen → __fopen)
Max depth: 24 levels
```

### 4. eBPF Enforcer (`sentinel.bpf.c`)

The kernel-side enforcement engine. Runs in eBPF context with zero-copy overhead on the hot (ALLOW) path.

**Hook Architecture:**

```
16 fentry hooks + 1 tracepoint = 17 enforcement points

┌─ Policy-checked hooks (use sentinel_check):
│   write, read, openat, execve, mmap, mprotect, connect,
│   memfd_create, prctl, sendmsg, dup2, close, ioctl
│
├─ Unconditional-block hooks:
│   ptrace, process_vm_writev, seccomp
│
└─ Fork tracking (tp_btf/sched_process_fork):
    Auto-enrolls child TGID in target_pid_map
```

**Enforcement Decision Tree (sentinel_check):**

```
1. Is TGID in target_pid_map? ──No──► return 0 (not monitored)
   │
   Yes
   │
2. Get syscall RIP from pt_regs, compute syscall_site = RIP - 2
   │
3. LPM trie lookup (vma_map) ──Miss──► BLOCK + SIGKILL
   │
   Hit → {module_id, base_addr}
   │
4. Compute offset = syscall_site - base_addr
   │
5. Map-of-Maps lookup: policy_registry[module_id][offset] ──Miss──► BLOCK
   │
   Hit → policy_value
   │
6. Phase 3 NR check: if (policy_value & CHECK_NR):
   │  expected_nr = policy_value & 0xFFFFFFFF
   │  if actual_nr ≠ expected_nr → NR_MISMATCH + SIGKILL
   │
7. Deep CFI check: if offset in cfi_policy:
   │  Walk user stack (bpf_get_stack)
   │  if caller_offset ∉ [range.start, range.end] → CFI_FAIL + SIGKILL
   │
8. ALLOW (hot path — zero audit overhead unless --audit)
```

## BPF Map Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    BPF Maps                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  target_pid_map (HASH)                                  │
│    key: u32 tgid  →  value: u32 (1)                    │
│                                                         │
│  vma_map (LPM_TRIE)                                    │
│    key: {prefixlen, addr_be}  →  {module_id, base_addr}│
│    1MB blocks, 44-bit prefix for x86-64 VMA coverage   │
│                                                         │
│  policy_registry (ARRAY_OF_MAPS)                        │
│    key: u32 module_id  →  value: inner_policy_map fd    │
│    Module 1 = Main binary                               │
│    Module 2 = Libc                                      │
│                                                         │
│  inner_policy (HASH, per-module template)               │
│    key: u64 offset  →  value: u64 policy_value          │
│    policy_value encoding:                               │
│      bit 32 clear: 1 = allow (any NR)                  │
│      bit 32 set:   bits[31:0] = expected syscall NR     │
│                                                         │
│  cfi_policy (HASH)                                      │
│    key: u64 offset  →  value: {u64 start, u64 end}     │
│    Valid caller offset range for Deep CFI               │
│                                                         │
│  audit_ringbuf (RINGBUF, 256KB)                         │
│    struct audit_event (48 bytes per event)              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Trust Chain

```
┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────┐
│ Compiler │───►│  Signer  │───►│   Loader     │───►│ BPF Enforcer │
│          │    │          │    │              │    │              │
│ Generates│    │ Ed25519  │    │ Verify sig   │    │ Check every  │
│ .sentinel│    │ sign hash│    │ via keyring  │    │ syscall RIP  │
│ .cfi     │    │ of all   │    │ Check revoke │    │ against      │
│ .imports │    │ sections │    │ Parse policy │    │ signed       │
│ .signature│   │          │    │ Call-graph   │    │ policy       │
│ (placeholder) │          │    │ BFS libc     │    │              │
└──────────┘    └──────────┘    └──────────────┘    └──────────────┘
     │                │                │                    │
     └── Build-time ──┘                └── Runtime ─────────┘
```

**Trust Assumptions:**
1. The build environment is not compromised (private key secure)
2. The kernel is trustworthy (eBPF runs in kernel context)
3. The Linux Keyring correctly manages public key access
4. BTF is available for fentry hook resolution

## Performance Model

**Hot Path (ALLOW):** 3 BPF map lookups + 1 comparison. Zero ring buffer I/O, zero `bpf_printk`. This is the common case for legitimate syscalls.

**Cold Path (BLOCK/CFI_FAIL/NR_MISMATCH):** Full audit event emission + `bpf_printk` diagnostics + `bpf_send_signal(SIGKILL)`. This only fires for actual security violations.

**Measured Overhead:** ~274 ns/syscall (48.58%) on the ALLOW hot path.

**Attack Surface Reduction:** Per-app libc filtering reduces the whitelisted libc syscall sites from ~435 (full glibc) to ~80 for a typical binary — an **81.6% reduction** in available gadgets.

## File Layout

```
sentinel-cc/
├── src/
│   ├── compiler/SentinelPass.cpp    # LLVM pass (intention extractor)
│   ├── common/sentinel_shared.h     # Shared types (BPF ↔ userspace)
│   ├── kernel/sentinel.bpf.c        # eBPF enforcer (kernel side)
│   └── runtime/
│       ├── loader.c                 # Signature verify + BPF loader
│       └── sign_tool.c              # Ed25519 signer
├── tests/                           # Victim binaries + red-team attacks
├── docs/                            # Documentation
├── Makefile                         # Build system
└── benchmark.sh                     # Performance measurement
```
