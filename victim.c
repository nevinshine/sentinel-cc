#include <unistd.h>

// Phase 1.2: Using Inline Syscalls with proper input/output constraints.
// Ensures RAX is correctly handled (input: syscall num, output: return val).

void safe_logger() {
  const char *msg = "SAFE\n";
  long ret;
  asm volatile("syscall"
               : "=a"(ret)
               : "a"(1),   // rax = 1 (write)
                 "D"(1),   // rdi = 1 (fd)
                 "S"(msg), // rsi = buf
                 "d"(5)    // rdx = count
               : "rcx", "r11", "memory");
}

void unsafe() {
  const char *msg = "UNSAFE\n";
  long ret;
  asm volatile("syscall"
               : "=a"(ret)
               : "a"(1),   // rax = 1 (write)
                 "D"(1),   // rdi = 1 (fd)
                 "S"(msg), // rsi = buf
                 "d"(7)    // rdx = count
               : "rcx", "r11", "memory");
}

// Force linker to keep the signature section
extern char __sentinel_signature[];

int main() {
  // Create a reference to the signature so linker doesn't strip it
  // The Pass will provide the definition.
  __asm__ volatile("" : : "r"(__sentinel_signature));

  safe_logger();
  unsafe();
  return 0;
}
