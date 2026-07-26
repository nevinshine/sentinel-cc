# Sentinel-CC: Threats to Validity (Limitations)

While Sentinel-CC bridges the semantic gap between compile-time intent and runtime enforcement, there are several architectural constraints and limitations inherent to this approach.

## 1. Toolchain Dependency
- **LLVM Exclusivity:** The semantic extraction is heavily coupled to the LLVM infrastructure (`MachineFunctionPass`, `BlockAddress`). Compiling code with GCC or other toolchains will result in binaries entirely devoid of Sentinel-CC metadata, rendering them unenforceable in strict mode.

## 2. Operating System Coupling
- **Linux and eBPF:** The enforcement mechanism relies exclusively on modern Linux kernel features (eBPF and the LSM hooking framework). The architecture is not portable to Windows, macOS, or legacy Linux kernels lacking `bpf_lsm_sys_enter` capabilities.

## 3. Dynamic Code Generation (JIT)
- **Unmapped Execution:** Applications that generate machine code dynamically at runtime (e.g., V8 JavaScript engine, JVM, Python ctypes) cannot be statically tracked by a compiler pass. Syscalls originating from dynamically allocated executable pages will fail the `LPM_TRIE` bounds check unless explicit runtime support (a JIT-to-Sentinel API) is added.

## 4. Shared Libraries
- **Static vs. Dynamic Linking:** The current implementation has been evaluated heavily against statically compiled code or dynamically linked code where the system calls are intercepted via standard libc wrapper functions. If a third-party shared library (`.so`) executes inline assembly syscalls and was not compiled with Sentinel-CC, those syscall sites will not be recorded in the binary's `.llvm.syscall.bounds` section. 
- **Enforcement Gap:** The eBPF runtime must currently treat uninstrumented shared libraries either permissively (creating a bypass vector) or strictly (breaking legitimate library functionality). Future work must address merging metadata from dynamically loaded `.so` objects.

## 5. Scope of Tracking
- **Libc Wrappers:** The pass currently tracks a hardcoded, exhaustive list of POSIX libc wrappers (`write`, `open`, `fprintf`, etc.). If a program utilizes an esoteric or custom userspace library that directly calls the syscall interrupt without passing through the tracked wrappers, the compiler will fail to map the site.
