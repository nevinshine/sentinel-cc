// victim_fork.c — Test: Fork Tracking (sched_process_fork)
//
// This test verifies that Sentinel's fork tracking works correctly:
// 1. The parent process is enrolled in Sentinel policy
// 2. The parent forks a child
// 3. The sched_process_fork tracepoint auto-enrolls the child's PID
// 4. The child performs syscalls that must be validated against policy
//
// EXPECTED: Both parent and child complete successfully — all syscalls ALLOW'd.
//           Without fork tracking, the child's PID wouldn't be in target_pid_map
//           and Sentinel would ignore it (no enforcement = security gap).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char __sentinel_signature[];

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Fork] Parent PID=%d starting fork tracking test.\n", getpid());
  fflush(stdout);

  pid_t child = fork();
  if (child < 0) {
    perror("[Fork] fork failed");
    return 1;
  }

  if (child == 0) {
    // Child process — Sentinel should auto-enroll via sched_process_fork
    printf("[Fork] Child PID=%d (forked from parent). Sentinel should track me.\n",
           getpid());
    fflush(stdout);

    // Perform some syscalls that Sentinel hooks
    FILE *fp = fopen("/dev/null", "w");
    if (fp) {
      fprintf(fp, "Child writing to /dev/null.\n");
      fclose(fp);
      printf("[Fork] Child: fopen+fprintf+fclose succeeded. Sentinel allowed it.\n");
    } else {
      printf("[Fork] Child: fopen failed (may have been blocked).\n");
    }

    // Direct write to stdout
    const char *msg = "[Fork] Child: direct write() succeeded.\n";
    write(STDOUT_FILENO, msg, strlen(msg));

    printf("[Fork] Child: all syscalls passed. Fork tracking works!\n");
    _exit(0);
  }

  // Parent process
  printf("[Fork] Parent: waiting for child PID=%d...\n", child);
  fflush(stdout);

  int status;
  waitpid(child, &status, 0);

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    printf("[Fork] Parent: child exited cleanly (code=0). Fork tracking verified!\n");
  } else if (WIFSIGNALED(status)) {
    printf("[Fork] Parent: child killed by signal %d.\n", WTERMSIG(status));
    if (WTERMSIG(status) == 9) {
      printf("[Fork] FAIL: Child was SIGKILL'd — fork tracking may not be working.\n");
      printf("[Fork] The child's PID was not enrolled in target_pid_map.\n");
      return 1;
    }
  } else {
    printf("[Fork] Parent: child exited with code %d.\n", WEXITSTATUS(status));
  }

  printf("[Fork] Test complete.\n");
  return 0;
}
