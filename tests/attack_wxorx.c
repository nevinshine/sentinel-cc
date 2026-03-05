// attack_wxorx.c — Red Team Test: W^X Violation via mprotect
//
// ATTACK: Allocate normal memory, write shellcode into it, then use
//         mprotect() to flip it to executable. This is a more sophisticated
//         version of the shellcode attack — it avoids mmap(PROT_EXEC) by
//         doing the permission change after writing.
//
// EXPECTED: Sentinel hooks __x64_sys_mprotect. When the injected shellcode
//           executes a 'syscall' from the mprotect'd region, that address
//           is NOT in any known VMA → SIGKILL.
//
// BONUS: The mprotect() call itself exercises the mprotect hook. If the
//        binary wasn't compiled to call mprotect, even THAT call might be
//        flagged (depending on whether libc's mprotect is whitelisted).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern char __sentinel_signature[];

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] W^X Violation Test (mprotect attack)\n");

  // Step 1: Allocate RW memory (no exec)
  size_t page_size = 4096;
  void *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    perror("[Attack] mmap");
    return 1;
  }

  printf("[Attack] RW page at %p\n", page);

  // Step 2: Write shellcode (write(1, "PWNED\n", 6) + exit(0))
  unsigned char shellcode[] = {
      0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1 (write)
      0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1 (stdout)
      0x48, 0x8d, 0x35, 0x11, 0x00, 0x00, 0x00, // lea rsi, [rip+17]
      0x48, 0xc7, 0xc2, 0x06, 0x00, 0x00, 0x00, // mov rdx, 6
      0x0f, 0x05,                                 // syscall ← ATTACK
      0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60 (exit)
      0x48, 0x31, 0xff,                           // xor rdi, rdi
      0x0f, 0x05,                                 // syscall (exit)
      // "PWNED\n"
      0x50, 0x57, 0x4e, 0x45, 0x44, 0x0a};

  memcpy(page, shellcode, sizeof(shellcode));

  printf("[Attack] Shellcode written to RW page.\n");

  // Step 3: mprotect — flip from RW to RX (the W^X violation)
  printf("[Attack] Calling mprotect to make page executable...\n");
  fflush(stdout);

  if (mprotect(page, page_size, PROT_READ | PROT_EXEC) != 0) {
    perror("[Attack] mprotect failed (possibly blocked by Sentinel)");
    printf("[OK] mprotect was blocked or failed — Sentinel may have intervened.\n");
    munmap(page, page_size);
    return 0;
  }

  printf("[Attack] mprotect succeeded. Jumping to shellcode...\n");
  printf("[Attack] If you see the attack payload below, Sentinel FAILED.\n");
  fflush(stdout);

  // Step 4: Execute the shellcode
  void (*payload)(void) = (void (*)(void))page;
  payload();

  // Should never reach here
  printf("[FAIL] Attack succeeded! Sentinel did NOT block W^X shellcode.\n");
  munmap(page, page_size);
  return 1;
}
