# Sentinel-CC Evaluation Checklist

To ensure all experimental data is reproducible and rigorously gathered, every benchmark executed for Sentinel-CC must record the following metadata and adhere to this methodology.

## Methodology

- **Repetitions:** Every benchmark must be run a minimum of 5 times (unless specified otherwise).
- **Statistical Rigor:** All results must report the **mean** and the **standard deviation**.
- **Cold vs. Hot Cache:** Explicitly state whether the system caches were dropped (e.g., `echo 3 > /proc/sys/vm/drop_caches`) prior to the benchmark.
- **Raw Measurements:** Keep raw JSON or CSV output for all runs to enable independent verification.

## Hardware & Environment Checklist

For every execution environment (e.g., CloudLab node), record the following profile:

- **CPU Model:** (e.g., `lscpu | grep "Model name"`)
- **RAM Capacity:** (e.g., `free -g`)
- **Kernel Version:** (e.g., `uname -r`)
- **OS Distribution:** (e.g., `cat /etc/os-release`)

## Toolchain Checklist

- **LLVM Version:** (e.g., `clang --version`)
- **Optimization Level:** (e.g., `-O0`, `-O2`, `-Os`)
- **Compiler Flags:** (e.g., `-flto`, `-fpass-plugin=...`)

*By strictly adhering to this checklist, Sentinel-CC moves from a proof-of-concept prototype to a verifiable systems research artifact.*
