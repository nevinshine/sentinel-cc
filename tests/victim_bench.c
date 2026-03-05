// victim_bench.c — Sentinel-CC Syscall Latency Microbenchmark
// Measures per-syscall overhead of eBPF enforcement by timing
// a tight write(2) loop to /dev/null under CLOCK_MONOTONIC.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS 1000000
#define WARMUP     1000

int main(void) {
  int fd = open("/dev/null", O_WRONLY);
  if (fd < 0) {
    perror("open /dev/null");
    return 1;
  }

  // Warmup: prime caches, page tables, BPF JIT
  for (int i = 0; i < WARMUP; i++)
    write(fd, "w", 1);

  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);

  for (int i = 0; i < ITERATIONS; i++)
    write(fd, "a", 1);

  clock_gettime(CLOCK_MONOTONIC, &end);

  long long elapsed_ns =
      (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
  long long avg_ns = elapsed_ns / ITERATIONS;

  printf("BENCH_ITERATIONS=%d\n", ITERATIONS);
  printf("BENCH_TOTAL_NS=%lld\n", elapsed_ns);
  printf("BENCH_AVG_NS=%lld\n", avg_ns);

  close(fd);
  return 0;
}
