# Sentinel-CC Evaluation Plan

This document outlines the rigorous experiments designed to validate the core thesis: that compiler-generated semantic metadata provides superior accuracy, stability, and scale compared to binary analysis heuristics.

## Research Questions
- **RQ1:** Can compiler-generated semantic metadata accurately represent runtime syscall behavior?
- **RQ2:** How stable is the metadata across compiler optimizations?
- **RQ3:** What are the compile-time, binary-size, and runtime costs?
- **RQ4:** What advantages and limitations does compiler-integrated semantic analysis have compared with existing approaches?

## Experiment 1: Optimization Stability (Addresses RQ2)
**Goal:** Prove that compiler optimizations do not orphan or invalidate the metadata.
**Method:** 
1. Compile a real-world application (e.g., SQLite) across `-O0`, `-O1`, `-O2`, `-O3`, and `-Os`.
2. Extract the `.llvm.syscall.bounds` metadata.
3. Compare the variance in syscall entry counts and section size.

## Experiment 2: Precision & Ground Truth (Addresses RQ1 & RQ4)
**Goal:** Demonstrate the "semantic gap" that binary analysis suffers from.
**Method:**
1. Disassemble the compiled binary using `objdump -d`.
2. Write a naive binary heuristic script that identifies `callq` instructions targeting known syscall wrappers.
3. Compare the binary heuristic hits against the compiler's emitted semantic metadata.
4. Measure True Positives, False Positives (lost to inlining/optimization), and False Negatives (missed by binary heuristics).

## Experiment 3: Metadata Size Overhead (Addresses RQ3)
**Goal:** Quantify the ELF binary bloat introduced by Sentinel-CC.
**Method:**
1. Compile large real-world applications with the pass enabled.
2. Measure the exact byte size of `.llvm.syscall.bounds`.
3. Express the size as a percentage of the total executable `.text` segment.

## Experiment 4: Compilation Overhead (Addresses RQ3)
**Goal:** Quantify the build-time cost of the analysis pass.
**Method:**
1. Clean build real-world applications using vanilla `clang`.
2. Clean build using `clang` + `SentinelPass.so`.
3. Compare absolute build times and percentage overhead.

## Experiment 5: Runtime Enforcement Overhead (Addresses RQ3)
**Goal:** Measure the latency introduced by the kernel verification.
**Method:**
1. Profile `loader.c` startup time.
2. Run a high-throughput microbenchmark (e.g., `lmbench` `lat_syscall` or `dd` I/O loops).
3. Compare baseline throughput against Sentinel-CC enforcement mode.

## Experiment 6: Real-World Workloads
All experiments will be conducted against a diverse suite of C applications:
- **SQLite:** File I/O, mature, complex codebase.
- **curl:** Networking client.
- **BusyBox:** Many disparate UNIX utilities.
- **Redis:** High-throughput network server.
- **nginx:** Production-grade web server.
