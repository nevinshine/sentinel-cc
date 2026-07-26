# Sentinel-CC Semantic Contract

## 1. Problem Statement
Binary-level control-flow integrity (CFI) and syscall filtering tools rely on fragile heuristics to reverse-engineer application intent from machine code. This semantic gap leads to over-privileged policies or false-positive enforcement blocks. Sentinel-CC bridges this gap by shifting the burden of trust to the compiler, which possesses authoritative knowledge of the program's intended semantics, and explicitly exporting this intent into a verifiable metadata format for the kernel to enforce.

## 2. Metadata Format (`.llvm.syscall.bounds`)
Sentinel-CC explicitly embeds its semantic analysis into the compiled object files under a dedicated ELF section: `.llvm.syscall.bounds`.

Because real-world applications are compiled from multiple translation units, the system linker aggregates these sections across object files. The `.llvm.syscall.bounds` section consists of one or more concatenated `sentinel_header` blocks, each followed by an array of `policy_entry` structs.

### Binary Layout
```c
// 1. The Header (9 bytes packed)
struct sentinel_header {
  char magic[4];       // Must be "\x7FSEN"
  uint8_t version;     // Currently 1
  uint32_t count;      // Number of policy_entry items following this header
} __attribute__((packed));

// 2. The Entry (24 bytes packed)
struct policy_entry {
  uint64_t site_addr;  // The LLVM BlockAddress representing the syscall site
  uint64_t func_addr;  // The address of the enclosing function
  int64_t syscall_nr;  // Encoding: 0 = "any", >0 = (Syscall Number + 1)
} __attribute__((packed));
```

## 3. Compiler Guarantees
The LLVM pass (`SentinelPass.so`) guarantees the following semantic properties before lowering to machine code:
- **Optimization Stability:** The `BlockAddress` constructs track the IR basic blocks throughout the optimization pipeline (`-O0` through `-Os`). We guarantee that standard inlining and constant propagation do not orphan the metadata; the recorded addresses remain synced with the final executable code layout.
- **Inline Assembly:** The pass parses `inline asm` strings for explicit `syscall` or `int 0x80` instructions. It attempts to resolve the `RAX` constraint to extract the exact syscall number at compile time.
- **libc Wrappers:** The pass intercepts standard POSIX wrappers and maps them to their respective syscall numbers. For buffered I/O wrappers (like `fprintf`), the compiler flags the site as `any` (wildcard) due to underlying flush operations.

## 4. Runtime Assumptions
The userspace loader (`loader.c`) acts as the intermediary, lifting the compiler's semantic contract into kernel-space.
- **Structural Integrity:** The loader assumes the target binary has NOT been subjected to binary obfuscators that arbitrarily shift code post-compilation (e.g., self-modifying code or extreme packer transformations).
- **Linkage:** It assumes the ELF symbol table and section headers accurately reflect the runtime memory mapping of the `.text` segment.

## 5. Enforcement Guarantees
The kernel enforces the policy using an `LSM` (Linux Security Module) hook attached to `bpf_lsm_sys_enter`.
- **Verification:** When a process issues a syscall, the eBPF program extracts the userspace instruction pointer (`RIP`) that triggered the trap.
- **Lookup:** It performs an exact lookup against the `LPM_TRIE` map populated by the loader.
- **Enforcement:** If the `RIP` is not found in the bounds map, or if the issued syscall number does not match the bound number (and is not flagged as a wildcard), the eBPF runtime intercepts and blocks the execution.

## 6. Failure Modes
- **Shared Libraries (.so):** Syscalls originating from dynamically linked libraries (e.g., `libc.so`) that were not compiled with Sentinel-CC will trigger enforcement blocks unless explicitly mapped or bypassed.
- **JIT Compilation:** Dynamically generated code (e.g., V8, JVM) cannot be statically tracked by the LLVM pass, representing a fundamental limitation of static metadata.
- **Hand-written Assembly:** Assembly files compiled without passing through the LLVM IR pipeline will lack semantic metadata.

## 7. Versioning
The metadata format is strictly versioned via the `version` field in the `sentinel_header`.
- **Current Version:** `1`
- **Compatibility:** The loader will explicitly reject execution if the `version` field does not match the expected format (currently `1`), ensuring that outdated or malformed metadata structures do not lead to undefined enforcement behavior.
