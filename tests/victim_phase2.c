#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

// Phase 2 Victim: Uses libc (Shared Library)
// This tests if Sentinel can handle ASLR and Map-of-Maps lookups.

// Force linker to keep signature section
extern char __sentinel_signature[];

int main() {
  // Reference signature to prevent stripping
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Victim] Hello from Phase 2! Calling printf (which calls write in "
         "libc)...\n");

  // Explicit libc call
  FILE *fp = fopen("/dev/null", "w");
  if (fp) {
    fprintf(fp, "[Victim] Writing to /dev/null via libc...\n");
    fclose(fp);
  }

  printf("[Victim] Success! I survived the Sentinel.\n");
  return 0;
}
