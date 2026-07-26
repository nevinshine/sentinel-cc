# Sentinel-CC Evaluation Results

This document presents the rigorous experimental results evaluating Sentinel-CC's overhead across various operations on CloudLab (Ubuntu 22.04 LTS, kernel 6.5.0, HP012).

## Experiment 5B: Enforcement Microbenchmarks (10M Iterations)

To measure the core overhead of our eBPF syscall interception pipeline (`kprobe` tracepoints + LPM trie module resolution + inner hash map verification), we ran an identical benchmark natively and under Sentinel-CC in permissive mode. Note that `getpid` is not actively hooked by our policy, showing 0 overhead, acting as a control.

| Operation            | Native (ops/sec)          | Sentinel (ops/sec)        | Overhead (%)   |
|----------------------|---------------------------|---------------------------|----------------|
| getpid               | 2,544,839 ± 16,386        | 2,559,465 ± 11,819        | -0.57%         |
| write                | 2,257,370 ± 6,984         | 1,770,564 ± 4,944         | 21.57%         |
| read                 | 2,262,415 ± 9,220         | 1,785,194 ± 12,765        | 21.09%         |
| openat+close         | 520,946 ± 1,467           | 462,549 ± 627             | 11.21%         |
| mmap+mprotect        | 525,156 ± 1,640           | 468,314 ± 2,276           | 10.82%         |

### Analysis of Microbenchmarks
Our eBPF intercept introduces roughly 21% overhead to raw `read()` and `write()` operations, representing a worst-case scenario since these syscalls do very little work in the kernel compared to the eBPF invocation itself. In heavier syscalls like `mmap` or `openat`, the eBPF overhead accounts for only ~11% of the total execution time. 

## Experiment 5C: Macrobenchmarks (SQLite)

Microbenchmarks often over-represent the cost of eBPF invocation because real applications do not invoke syscalls in a tight loop. To understand the actual cost on real applications, we benchmarked SQLite.

| Application     | Native                    | Sentinel                  | Overhead (%)   |
|-----------------|---------------------------|---------------------------|----------------|
| SQLite          | 2,347,364 ± 640,696 ops/s | 1,779,526 ± 66,685 ops/s  | 24.19%         |

### Analysis of Macrobenchmarks
SQLite relies heavily on I/O operations (`read` and `write`), meaning the 21% overhead from our microbenchmarks is fully realized in the macrobenchmark. While 24.19% is non-negligible, it is highly competitive with state-of-the-art software-based CFI and syscall interception tools (e.g., ptrace interception which often imposes 100%+ overhead).
