// attack_vm_writev.c — Red Team Test: Cross-Process Memory Write
//
// ATTACK: Uses process_vm_writev() to write directly into another process's
//         memory. This bypasses all file-based protections — the attacker can
//         overwrite code, inject shellcode, or modify data in a victim process.
//
// EXPECTED: Sentinel's fentry/__x64_sys_process_vm_writev hook fires as an
//           UNCONDITIONAL BLOCK — the process is killed with SIGKILL regardless
//           of policy. This syscall is never legitimate for Sentinel-protected code.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

extern char __sentinel_signature[];

// Inline syscall for process_vm_writev (NR=311)
static long raw_process_vm_writev(pid_t pid, const struct iovec *local,
                                  unsigned long liovcnt,
                                  const struct iovec *remote,
                                  unsigned long riovcnt,
                                  unsigned long flags) {
  long ret;
  register long r10 __asm__("r10") = (long)remote;
  register long r8  __asm__("r8")  = (long)riovcnt;
  register long r9  __asm__("r9")  = (long)flags;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(311),        // __NR_process_vm_writev
                     "D"((long)pid),  // pid
                     "S"(local),      // local_iov
                     "d"(liovcnt),    // liovcnt
                     "r"(r10),        // remote_iov
                     "r"(r8),         // riovcnt
                     "r"(r9)          // flags
                   : "rcx", "r11", "memory");
  return ret;
}

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] Cross-Process Memory Write Test (process_vm_writev)\n");
  printf("[Attack] Attempting to write into our own memory via syscall...\n");
  fflush(stdout);

  // Target: write into our own address space (pid=self) as a demonstration.
  // In a real attack, this would target another Sentinel-protected process.
  char target_buf[64] = "ORIGINAL_DATA";
  const char *evil = "PWNED_BY_VM_WRITEV";

  struct iovec local_iov  = { .iov_base = (void *)evil, .iov_len = strlen(evil) };
  struct iovec remote_iov = { .iov_base = target_buf,   .iov_len = strlen(evil) };

  pid_t self = getpid();
  printf("[Attack] PID=%d, writing to buffer at %p...\n", self, target_buf);
  fflush(stdout);

  // THIS is the attack — Sentinel should unconditionally block this
  long ret = raw_process_vm_writev(self, &local_iov, 1, &remote_iov, 1, 0);

  if (ret >= 0) {
    printf("[FAIL] process_vm_writev succeeded! Wrote %ld bytes.\n", ret);
    printf("[FAIL] Buffer now: '%s'\n", target_buf);
    printf("[FAIL] Cross-process memory write is UNBLOCKED!\n");
    return 1;
  } else {
    printf("[OK] process_vm_writev failed (ret=%ld) — Sentinel blocked it.\n", ret);
    return 0;
  }
}
