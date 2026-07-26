# Sentinel-CC Architecture

Sentinel-CC is built on a tripartite architecture designed to bridge the semantic gap between compile-time knowledge and runtime enforcement.

## 1. The Compiler Pass (Producer)
**Component:** `src/compiler/SentinelPass.cpp`
**Role:** An LLVM `MachineFunctionPass` (currently migrating from `ModulePass`) that operates late in the compilation pipeline.
**Function:** 
- Analyzes the Intermediate Representation (IR) to identify explicit syscall invocations (via inline assembly) and standard library syscall wrappers.
- Emits a custom ELF section (`.llvm.syscall.bounds`) containing a semantic map of valid syscall sites.
- Because it operates before lowering to machine code, it is immune to the ambiguities that plague binary analysis (e.g., inlining, constant propagation, and register allocation).

## 2. The Userspace Loader (Intermediary)
**Component:** `src/runtime/loader.c`
**Role:** The bridge between the compiled binary and the kernel.
**Function:**
- Parses the target ELF binary.
- Extracts the `.llvm.syscall.bounds` metadata.
- Adjusts the `site_addr` virtual addresses by resolving Position Independent Executable (PIE) offsets.
- Populates the kernel's eBPF `LPM_TRIE` map with the valid execution bounds.

## 3. The eBPF-LSM Runtime (Consumer)
**Component:** `src/runtime/sentinel.bpf.c`
**Role:** The kernel-space enforcement mechanism.
**Function:**
- Attaches to the `bpf_lsm_sys_enter` hook.
- Upon any system call, traverses the execution stack to extract the userspace `RIP` (Instruction Pointer) that triggered the trap.
- Performs an O(1) lookup in the `LPM_TRIE` map.
- If the `RIP` is missing, or if the syscall number violates the bounded policy, the execution is blocked (`-EPERM`) and a SIGKILL is optionally dispatched to the violating thread.
