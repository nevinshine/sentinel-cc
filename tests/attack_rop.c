// attack_rop.c — Red Team Test: ROP-Style Gadget Reuse
//
// ATTACK: Simulates a Return-Oriented Programming attack. The binary has a
//         legitimate 'syscall' instruction inside whitelisted_write(). The
//         attacker overwrites a function pointer to jump DIRECTLY to that
//         'syscall' instruction, bypassing the normal call path.
//
// WHY THIS MATTERS: If Sentinel only checks "is there a syscall instruction
//         at this offset?" without CFI, a ROP chain could reuse any whitelisted
//         gadget. Deep CFI (Phase 2.2) should catch the invalid caller.
//
// EXPECTED: Sentinel KILLS this because the 'syscall' at the gadget offset
//           is called from an unauthorized location (main, not whitelisted_write).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char __sentinel_signature[];

// Legitimate function with a 'syscall' instruction — this gets whitelisted
__attribute__((noinline)) void whitelisted_write(const char *msg, int len) {
  long ret;
  asm volatile("syscall"
               : "=a"(ret)
               : "a"(1),    // write
                 "D"(1),    // stdout
                 "S"(msg),  // buf
                 "d"(len)   // count
               : "rcx", "r11", "memory");
}

// Attacker's target: a function that SHOULD NOT be allowed to invoke the
// whitelisted syscall gadget directly
__attribute__((noinline)) void attacker_controlled() {
  const char *evil_msg = "[FAIL] ROP gadget reuse succeeded! Sentinel FAILED.\n";

  // In a real ROP attack, the attacker would overwrite a return address on the
  // stack to jump to the 'syscall' instruction inside whitelisted_write.
  // We simulate this by calling whitelisted_write from an unauthorized caller.
  //
  // If CFI is active: Sentinel checks stack[1] (caller) and sees it's not
  // in the valid caller range → SIGKILL
  // If CFI is NOT active: This will succeed (the offset is whitelisted)
  whitelisted_write(evil_msg, strlen(evil_msg));
}

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Attack] ROP Gadget Reuse Test\n");
  printf("[Attack] Step 1: Legitimate call (should succeed)...\n");
  fflush(stdout);

  // This is the legitimate call path
  const char *safe = "[OK] Legitimate write succeeded.\n";
  whitelisted_write(safe, strlen(safe));

  printf("[Attack] Step 2: Simulated ROP — calling from unauthorized site...\n");
  fflush(stdout);

  // This simulates a ROP gadget reuse — same syscall, wrong caller
  attacker_controlled();

  // If we get here, the ROP simulation wasn't caught
  printf("[WARN] Reached end — CFI may not be active for this binary.\n");
  return 0;
}
