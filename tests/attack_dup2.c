// attack_dup2.c — Red Team Test: File Descriptor Hijacking via dup2
//
// ATTACK: Uses dup2() to redirect stdout (fd 1) to a file, then performs
//         a write that the user thinks goes to the terminal but actually
//         goes to the attacker-controlled file. Scenarios:
//         - Redirect stderr to /dev/null (hide error messages)
//         - Redirect stdin from a pipe (inject commands)
//         - Redirect a logging fd to a fake file (tamper with audit trail)
//
// EXPECTED: Sentinel's fentry/__x64_sys_dup2 hook fires and validates the
//           syscall against the policy map. If the binary wasn't compiled
//           to call dup2(), the process is killed.

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char __sentinel_signature[];

// Inline syscall for dup2 (NR=33)
static long raw_dup2(int oldfd, int newfd) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(33),       // __NR_dup2
                     "D"((long)oldfd),
                     "S"((long)newfd)
                   : "rcx", "r11", "memory");
  return ret;
}

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] FD Hijack Test (dup2)\n");
  printf("[Attack] Attempting to redirect stdout to /dev/null...\n");
  fflush(stdout);

  // Step 1: Open /dev/null
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull < 0) {
    perror("[Attack] open /dev/null");
    return 1;
  }

  // Step 2: dup2 — redirect stdout to /dev/null
  printf("[Attack] Calling dup2(%d, 1) to hijack stdout...\n", devnull);
  fflush(stdout);

  // THIS is the attack — Sentinel should block dup2 if not in policy
  long ret = raw_dup2(devnull, STDOUT_FILENO);

  if (ret >= 0) {
    // stdout is now /dev/null — this write disappears silently
    // We can't printf anymore (it would go to /dev/null)
    // Use stderr instead to report
    fprintf(stderr, "[FAIL] dup2 succeeded! stdout is now /dev/null.\n");
    fprintf(stderr, "[FAIL] Audit trail could be silently suppressed!\n");

    // Restore stdout for clean exit
    raw_dup2(devnull, STDOUT_FILENO); // Already gone, just close
    close(devnull);
    return 1;
  } else {
    printf("[OK] dup2 failed (ret=%ld) — Sentinel blocked it.\n", ret);
    printf("[OK] FD hijacking is not allowed for this binary.\n");
    close(devnull);
    return 0;
  }
}
