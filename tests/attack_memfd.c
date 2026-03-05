// attack_memfd.c — Red Team Test: Fileless Malware via memfd_create
//
// ATTACK: Uses memfd_create() to create an anonymous in-memory file, writes
//         shellcode (or an ELF) into it, then execve()s the fd path.
//         This is the classic "fileless malware" technique — no file on disk.
//
// EXPECTED: Sentinel's fentry/__x64_sys_memfd_create hook fires and blocks
//           the memfd_create() syscall, killing the process with SIGKILL.
//           The attack never gets far enough to write or exec anything.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern char __sentinel_signature[];

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

// Inline syscall for memfd_create (NR=319) — bypasses libc wrapper
static long raw_memfd_create(const char *name, unsigned int flags) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(319),  // __NR_memfd_create
                     "D"(name), // name
                     "S"(flags) // flags
                   : "rcx", "r11", "memory");
  return ret;
}

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] Fileless Malware Test (memfd_create)\n");
  printf("[Attack] Creating anonymous in-memory file...\n");
  fflush(stdout);

  // Step 1: memfd_create — this is the attack vector Sentinel should block
  long fd = raw_memfd_create("evil_payload", MFD_CLOEXEC);
  if (fd < 0) {
    printf("[OK] memfd_create failed (ret=%ld) — Sentinel may have blocked it.\n", fd);
    printf("[OK] If we weren't killed, the syscall was denied.\n");
    return 0;
  }

  printf("[FAIL] memfd_create succeeded! fd=%ld\n", fd);
  printf("[FAIL] An attacker could now write an ELF and execve /proc/self/fd/%ld\n", fd);

  // Step 2: Write payload (demonstrate the threat)
  const char *payload = "#!/bin/echo PWNED";
  write(fd, payload, strlen(payload));

  // Step 3: Try to execute (this would be the actual attack)
  char fd_path[64];
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%ld", fd);
  printf("[FAIL] Attempting execve on memfd...\n");

  // This would replace the current process with the payload
  // execve(fd_path, (char *[]){fd_path, NULL}, NULL);

  printf("[FAIL] memfd_create attack vector is OPEN!\n");
  close(fd);
  return 1;
}
