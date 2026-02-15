#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Gadget: A syscall wrapper that we will whitelist
// We use noinline to prevent the compiler from optimizing call sites
__attribute__((noinline)) void do_write(const char *msg, int len) {
  // raw syscall 1 (write) to stdout (1)
  // We hardcode the syscall to ensure a stable offset for our test loader
  // Cast to long to force 64-bit register allocation at -O0
  long _msg = (long)msg;
  long _len = (long)len;
  asm volatile("mov $1, %%rax\n\t"
               "mov $1, %%rdi\n\t"
               "movq %0, %%rsi\n\t"
               "movq %1, %%rdx\n\t"
               "syscall"
               :
               : "r"(_msg), "r"(_len)
               : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory");
}

__attribute__((noinline)) void safe_caller() {
  char *msg = "[SAFE] Hello from safe_caller\n";
  do_write(msg, strlen(msg));
}

__attribute__((noinline)) void unsafe_caller() {
  char *msg = "[UNSAFE] Hello from unsafe_caller (Should Die)\n";
  do_write(msg, strlen(msg));
}

// Force linker to keep signature section
extern char __sentinel_signature[];

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Victim] Deep CFI Test Starting...\n");

  // 1. Valid Call
  safe_caller();
  printf("[Victim] Safe call successful.\n");

  // 2. Invalid Call
  printf("[Victim] Attempting unsafe call...\n");
  unsafe_caller();

  // 3. Failure
  printf("[Victim] FAILED: Unsafe call was not blocked!\n");
  return 1;
}
