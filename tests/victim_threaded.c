#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

void *worker(void *arg) {
  long id = (long)arg;
  char buf[64];
  int len = snprintf(buf, sizeof(buf), "[Thread %ld] Alive. TID=%ld\n", id,
                     syscall(SYS_gettid));
  // Explicit write syscall (handled by libc policy)
  write(1, buf, len);
  return NULL;
}

// Force linker to keep signature section
extern char __sentinel_signature[];

int main() {
  __asm__ volatile("" : : "r"(__sentinel_signature));

  printf("[Main] Spawning 3 threads...\n");
  pthread_t t[3];

  for (long i = 0; i < 3; i++) {
    pthread_create(&t[i], NULL, worker, (void *)i);
  }

  for (int i = 0; i < 3; i++) {
    pthread_join(t[i], NULL);
  }

  printf("[Main] All threads finished successfully.\n");
  return 0;
}
