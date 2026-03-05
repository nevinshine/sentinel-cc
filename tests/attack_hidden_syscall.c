// attack_hidden_syscall.c — Red Team Test: Hidden Syscall Not in Policy
//
// ATTACK: The binary has TWO syscall sites:
//   1. write() — captured by the compiler pass → in .sentinel → whitelisted
//   2. execve() — manually injected AFTER compilation (simulated here by
//      putting it behind a conditional so the compiler can't easily see it)
//
// This tests the fundamental guarantee: ANY syscall instruction at an offset
// NOT in the .sentinel whitelist → process is killed.
//
// EXPECTED: The write() succeeds (whitelisted), but the manually crafted
//           execve() syscall at a non-whitelisted offset → SIGKILL.

#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char __sentinel_signature[];

// This function's inline syscall IS captured by the compiler pass
__attribute__((noinline)) void legitimate_write() {
  const char *msg = "[OK] Legitimate write succeeded.\n";
  long ret;
  asm volatile("syscall"
               : "=a"(ret)
               : "a"(1),           // write
                 "D"(1),           // stdout
                 "S"(msg),         // buf
                 "d"(strlen(msg))  // len
               : "rcx", "r11", "memory");
}

// This function has a DIFFERENT syscall (getpid) that the attacker planted.
// The compiler pass sees it and whitelists its offset — BUT the BPF enforcer
// checks the actual syscall NUMBER vs the expected NR in the policy.
//
// Phase 3 (syscall number binding) is ACTIVE: the policy encodes nr=39 for
// this site. If an attacker reused this offset for a different NR (e.g.,
// execve=59), the BPF enforcer detects NR_MISMATCH → SIGKILL.
__attribute__((noinline)) long hidden_getpid() {
  long ret;
  // Compiler pass captures this as a "syscall" site and whitelists it.
  // But the INTENT was write — this is getpid (nr=39).
  // This demonstrates the need for syscall-number-specific policies (Phase 3).
  asm volatile("syscall"
               : "=a"(ret)
               : "a"(39) // getpid — harmless but demonstrates the gap
               : "rcx", "r11", "memory");
  return ret;
}

// This is the REAL attack: an inline execve that tries to spawn a shell.
// The pass WILL capture the 'syscall' instruction, so the offset IS whitelisted.
// This demonstrates that current Sentinel allows it because it only checks
// offset, not the syscall number. Phase 3 (argument validation) would block this.
__attribute__((noinline)) void attack_execve() {
  printf("[Attack] Attempting execve(\"/bin/sh\") from inline asm...\n");
  fflush(stdout);

  const char *path = "/bin/echo";
  const char *argv[] = {"/bin/echo", "[FAIL] execve succeeded!", NULL};
  const char *envp[] = {NULL};

  long ret;
  asm volatile("syscall"
               : "=a"(ret)
               : "a"(59),          // execve
                 "D"(path),        // filename
                 "S"(argv),        // argv
                 "d"(envp)         // envp
               : "rcx", "r11", "memory");

  // If execve fails (blocked by Sentinel or just fails), we continue
  printf("[Info] execve returned %ld (blocked or failed)\n", ret);
}

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] Hidden Syscall / Syscall-Number Confusion Test\n");
  printf("=========================================================\n");

  // Step 1: Legitimate — should pass
  printf("[Step 1] Legitimate write...\n");
  legitimate_write();

  // Step 2: getpid from a whitelisted offset — tests syscall-number blindness
  printf("[Step 2] getpid from whitelisted offset...\n");
  long pid = hidden_getpid();
  printf("[Info] getpid returned: %ld (offset was whitelisted, nr=39 matches)\n", pid);
  printf("[Note] Phase 3 NR binding is ACTIVE — wrong NR at this offset → SIGKILL.\n\n");

  // Step 3: execve — the dangerous one
  printf("[Step 3] Attempting execve from inline asm...\n");
  attack_execve();

  printf("\n[Summary] Phase 3 syscall-number binding is ACTIVE.\n");
  printf("[Summary] Each whitelisted offset has an expected NR. Mismatches → SIGKILL.\n");
  printf("[Summary] The execve attempt above should trigger NR_MISMATCH.\n");
  return 0;
}
