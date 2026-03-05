// attack_ptrace.c — Red Team Test: Anti-Debug / Ptrace Injection
//
// ATTACK: A malicious process tries to ptrace-attach to a Sentinel-protected
//         process. In a real attack, ptrace allows:
//         - Reading/writing victim memory
//         - Injecting syscalls (PTRACE_SYSCALL + register manipulation)
//         - Modifying RIP to redirect execution
//
// This test has the victim fork(). The child runs under Sentinel.
// The parent then tries to ptrace-attach to the child.
//
// EXPECTED: The ptrace() syscall triggers the fentry/__x64_sys_ptrace hook.
//           Since v3.0.0, ptrace is an UNCONDITIONAL BLOCK — any monitored
//           process calling ptrace is immediately killed with SIGKILL.
//
// NOTE: This test is designed to be run UNDER the Sentinel loader — the parent
//       process (which IS monitored) attempts ptrace, and Sentinel should block it.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char __sentinel_signature[];

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] Ptrace Injection Test\n");
  printf("[Attack] This process will attempt to ptrace-attach to a child.\n");
  printf("[Attack] Sentinel should block the ptrace() syscall.\n\n");
  fflush(stdout);

  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    return 1;
  }

  if (child == 0) {
    // Child: just sleep and exit
    printf("[Child] PID=%d, sleeping for 3 seconds...\n", getpid());
    fflush(stdout);
    sleep(3);
    printf("[Child] Exiting normally.\n");
    _exit(0);
  }

  // Parent: attempt ptrace attach
  // Give child a moment to start
  usleep(100000); // 100ms

  printf("[Parent] Attempting PTRACE_ATTACH to child PID=%d...\n", child);
  fflush(stdout);

  // THIS is the attack — ptrace() from a Sentinel-monitored process
  long ret = ptrace(PTRACE_ATTACH, child, NULL, NULL);

  if (ret == 0) {
    printf("[FAIL] ptrace ATTACH succeeded! Sentinel did NOT block it.\n");
    printf("[FAIL] An attacker could now inject code into the child.\n");

    // Clean up: detach
    waitpid(child, NULL, 0); // Wait for stop
    ptrace(PTRACE_DETACH, child, NULL, NULL);
  } else {
    printf("[OK] ptrace ATTACH failed: %s (errno=%d)\n", strerror(errno), errno);
    if (errno == EPERM) {
      printf("[OK] Permission denied — kernel or Sentinel blocked it.\n");
    } else {
      printf("[Info] Sentinel may have killed us before we got here,\n");
      printf("[Info] or the ptrace hook sent SIGKILL to this process.\n");
    }
  }

  // Wait for child
  kill(child, SIGTERM);
  waitpid(child, NULL, 0);

  printf("[Done] Ptrace test complete.\n");
  return 0;
}
