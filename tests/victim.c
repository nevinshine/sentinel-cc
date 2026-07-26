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

int main() {

  safe_logger();
  unsafe();
  return 0;
}
