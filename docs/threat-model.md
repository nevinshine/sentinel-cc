# Sentinel-CC Threat Model

## What Sentinel-CC Protects Against

### In Scope

| Threat | Mitigation |
|--------|-----------|
| **Binary Tampering** | Ed25519 signature over `.text + .sentinel + .sentinel_cfi + .sentinel_imports` — any modification is detected |
| **Unauthorized Syscalls** | Only compiler-whitelisted syscall sites are allowed; all others → SIGKILL |
| **ROP/JOP Attacks** | Redirecting execution to a valid syscall instruction at an unauthorized offset is blocked |
| **Code Injection** | `execve` and `mprotect` hooks prevent loading/executing unauthorized code |
| **Privilege Escalation via ptrace** | `ptrace` hook blocks unauthorized debugger attachment |
| **Network Exfiltration** | `connect` hook validates that network syscalls come from whitelisted sites |
| **Caller Spoofing** | Deep CFI validates the call stack, not just the syscall instruction location |
| **ASLR Bypass** | VMA mapping via `/proc/PID/maps` + LPM trie handles randomized addresses |
| **Thread Race Conditions** | TGID-based tracking covers all threads in a process |
| **Fileless Malware** | `memfd_create` hook unconditionally blocks anonymous executable creation |
| **Cross-Process Injection** | `process_vm_writev` hook unconditionally blocks cross-process memory writes |
| **Seccomp Tampering** | `seccomp` hook unconditionally prevents filter installation on monitored processes |
| **FD Exfiltration** | `sendmsg` hook validates SCM_RIGHTS fd passing against policy |
| **Revoked Key Replay** | Loader checks SHA-256 fingerprints against `/etc/sentinel/revoked_keys` |
| **Unreachable Libc Gadgets** | Per-app call-graph filtering only whitelists reachable syscall sites (81.6% reduction) |

### Out of Scope

| Threat | Reason |
|--------|--------|
| **Kernel Exploits** | Sentinel runs in eBPF (restricted kernel space) — a kernel exploit can bypass it |
| **Physical Access** | An attacker with physical access can replace the entire system |
| **Side-Channel Attacks** | Timing, Spectre, Meltdown — not addressable at the syscall level |
| **Supply Chain (Compiler)** | We trust the compiler. A malicious compiler could emit false policy |
| **Key Compromise** | If the Ed25519 private key is stolen, an attacker can sign malicious binaries. Mitigated by key rotation (`make key-rotate`) and revocation (`make key-revoke`). |
| **Data-Only Attacks** | Attacks that modify data (not control flow) without triggering new syscalls |

## Trust Assumptions

1. **Trusted Compiler:** The LLVM pass and the compilation toolchain are not compromised.
2. **Trusted Kernel:** The Linux kernel and eBPF verifier are functioning correctly.
3. **Secure Key Storage:** The Ed25519 private key is stored offline or in an HSM.
4. **Kernel Keyring Integrity:** The session keyring used for public key storage is not tampered with.
5. **BTF Availability:** The kernel exposes BTF for eBPF program attachment.

## Attack Scenarios

### Scenario 1: Modified Binary
**Attack:** Attacker modifies a byte in the `.text` section.
**Result:** Signature verification fails. Loader refuses to execute. ✓

### Scenario 2: ROP Chain Targeting Whitelisted Syscall
**Attack:** ROP chain jumps to a whitelisted `write()` call site with attacker-controlled arguments.
**Result:** The syscall site offset matches policy, but Deep CFI validates the *caller*. If the return address on the stack doesn't match the expected caller range → SIGKILL. ✓

### Scenario 3: dlopen() of Malicious Library
**Attack:** Binary loads a malicious `.so` that contains syscalls.
**Result:** The malicious library's VMA is not registered in the policy registry. Any syscall from it triggers "Unknown VMA" → SIGKILL. ✓

### Scenario 4: Thread Creates Unauthorized Syscall
**Attack:** A rogue thread (same TGID) executes a syscall not in the policy.
**Result:** TGID-based tracking catches it. The offset check fails → SIGKILL. ✓

### Scenario 5: Fileless Malware via memfd_create
**Attack:** Attacker creates anonymous in-memory file and execve()s it.
**Result:** Unconditional block on `__x64_sys_memfd_create` → SIGKILL before fd is created. ✓

### Scenario 6: Seccomp Filter Tampering
**Attack:** Attacker installs seccomp-BPF filter to interfere with Sentinel hooks.
**Result:** Unconditional block on `__x64_sys_seccomp` → SIGKILL. ✓

### Scenario 7: Cross-Process Memory Write
**Attack:** Attacker uses `process_vm_writev()` to inject code into another process.
**Result:** Unconditional block on `__x64_sys_process_vm_writev` → SIGKILL. ✓

### Scenario 8: Revoked Key Replay
**Attack:** Attacker signs a binary with a previously-compromised key.
**Result:** Loader checks `/etc/sentinel/revoked_keys` — SHA-256 fingerprint match → rejection. ✓

### Scenario 9: Unreachable Libc Gadget (Per-App Filtering)
**Attack:** Attacker ROP-chains into a libc function (e.g., `execve` wrapper) that the binary never imports.
**Result:** Call-graph BFS only whitelists reachable syscall sites — the gadget offset is not in the policy map → SIGKILL. ✓
