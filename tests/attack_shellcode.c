// attack_shellcode.c — Red Team Test: Runtime Shellcode Injection
//
// ATTACK: Allocate RWX memory via mmap, write raw 'syscall' bytes into it,
//         then jump to it. This simulates a classic buffer overflow → shellcode
//         injection attack.
//
// EXPECTED: Sentinel KILLS this process because the injected 'syscall'
//           instruction is at an address NOT in the .sentinel policy.
//           The VMA won't even be in the policy_registry → "Unknown VMA" → SIGKILL.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern char __sentinel_signature[];

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] Shellcode Injection Test\n");
  printf("[Attack] Allocating RWX memory...\n");

  // Step 1: mmap a page with READ+WRITE+EXEC (the classic W^X violation)
  void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    perror("[Attack] mmap failed");
    return 1;
  }

  printf("[Attack] RWX page at %p\n", page);

  // Step 2: Write raw shellcode — a write(1, "PWNED\n", 6) syscall
  //   mov rax, 1        ; syscall number for write
  //   mov rdi, 1        ; fd = stdout
  //   lea rsi, [rip+msg]; buf = "PWNED\n"
  //   mov rdx, 6        ; count = 6
  //   syscall            ; ← THIS is the attack. Not in .sentinel policy.
  //   ret
  unsigned char shellcode[] = {
      0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
      0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
      0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00, // lea rsi, [rip+10]
      0x48, 0xc7, 0xc2, 0x06, 0x00, 0x00, 0x00, // mov rdx, 6
      0x0f, 0x05,                                 // syscall  ← ATTACK POINT
      0xc3,                                       // ret
      // Embedded string "PWNED\n"
      0x50, 0x57, 0x4e, 0x45, 0x44, 0x0a};

  memcpy(page, shellcode, sizeof(shellcode));

  printf("[Attack] Shellcode written. Jumping to injected code...\n");
  printf("[Attack] If you see the attack payload below, Sentinel FAILED.\n");
  fflush(stdout);

  // Step 3: Jump to shellcode
  void (*payload)(void) = (void (*)(void))page;
  payload();

  // If we reach here, the attack succeeded (Sentinel failed)
  printf("[FAIL] Attack succeeded! Sentinel did NOT block shellcode.\n");
  munmap(page, 4096);
  return 1;
}
