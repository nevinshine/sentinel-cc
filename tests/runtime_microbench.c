#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#define ITERATIONS 10000000

double get_time_diff(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
}

void bench_getpid() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        getpid();
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = get_time_diff(&start, &end);
    printf("getpid:\t\t%.4fs\t(%.0f ops/sec)\n", elapsed, ITERATIONS / elapsed);
}

void bench_read_write() {
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        perror("open");
        return;
    }
    char buf[1] = {'a'};

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        write(fd, buf, 1);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = get_time_diff(&start, &end);
    printf("write:\t\t%.4fs\t(%.0f ops/sec)\n", elapsed, ITERATIONS / elapsed);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        read(fd, buf, 1);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = get_time_diff(&start, &end);
    printf("read:\t\t%.4fs\t(%.0f ops/sec)\n", elapsed, ITERATIONS / elapsed);
    
    close(fd);
}

void bench_openat_close() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        int fd = openat(AT_FDCWD, "/dev/null", O_RDONLY);
        close(fd);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = get_time_diff(&start, &end);
    // Since it's openat + close, ops/sec is derived from ITERATIONS iterations of both
    printf("openat+close:\t%.4fs\t(%.0f ops/sec)\n", elapsed, ITERATIONS / elapsed);
}

void bench_mmap_mprotect() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS / 100; i++) { // mmap is heavy, do 100k
        void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        mprotect(ptr, 4096, PROT_READ);
        munmap(ptr, 4096);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = get_time_diff(&start, &end);
    printf("mmap+mprotect:\t%.4fs\t(%.0f ops/sec)\n", elapsed, (ITERATIONS / 100) / elapsed);
}

int main() {
    printf("--- Sentinel-CC Runtime Microbenchmarks ---\n");
    printf("Iterations: %d\n\n", ITERATIONS);
    bench_getpid();
    bench_read_write();
    bench_openat_close();
    bench_mmap_mprotect();
    return 0;
}
