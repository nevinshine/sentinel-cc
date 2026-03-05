// attack_seccomp.c — Red Team Test: Seccomp Filter Tampering
//
// ATTACK: Installs a seccomp-BPF filter that would interfere with Sentinel's
//         enforcement by trapping or allowing syscalls before Sentinel's
//         fentry hooks fire. A sophisticated attacker could use seccomp to:
//         - ERRNO certain syscalls (making Sentinel think they didn't happen)
//         - TRAP to a signal handler that modifies registers
//         - Allow a subset of syscalls that Sentinel would block
//
// EXPECTED: Sentinel's fentry/__x64_sys_seccomp hook fires as an
//           UNCONDITIONAL BLOCK — seccomp(2) is never allowed for monitored
//           processes. The process is killed with SIGKILL.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern char __sentinel_signature[];

// Inline syscall for seccomp (NR=317)
static long raw_seccomp(unsigned int operation, unsigned int flags, void *args) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(317),           // __NR_seccomp
                     "D"((long)operation),
                     "S"((long)flags),
                     "d"(args)
                   : "rcx", "r11", "memory");
  return ret;
}

#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_SET_MODE_FILTER 1

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] Seccomp Filter Tampering Test\n");
  printf("[Attack] Attempting to install a seccomp-BPF filter...\n");
  printf("[Attack] This would interfere with Sentinel's enforcement.\n");
  fflush(stdout);

  // Step 1: Try seccomp STRICT mode (simplest — only allows read/write/exit/_exit)
  printf("[Attack] Calling seccomp(SECCOMP_SET_MODE_STRICT)...\n");
  fflush(stdout);

  // THIS is the attack — Sentinel should unconditionally block seccomp()
  long ret = raw_seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL);

  if (ret == 0) {
    printf("[FAIL] seccomp STRICT mode installed! Sentinel FAILED to block it.\n");
    printf("[FAIL] An attacker could now install arbitrary seccomp filters.\n");
    // In strict mode, only read/write/_exit/sigreturn are allowed
    // We can still write to report the failure
    const char *msg = "[FAIL] Seccomp is active — Sentinel's hooks may be bypassed!\n";
    write(STDOUT_FILENO, msg, 63);
    _exit(1);
  } else {
    printf("[OK] seccomp failed (ret=%ld) — Sentinel blocked it.\n", ret);
    printf("[OK] Monitored processes cannot install seccomp filters.\n");
    return 0;
  }
}
