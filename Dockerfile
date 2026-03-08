# Sentinel-CC Artifact Reproduction Image
# Builds the complete toolchain from source for USENIX artifact evaluation.
#
# Build:  docker build -t sentinel-cc .
# Run:    docker run --privileged sentinel-cc make test
# Shell:  docker run --privileged -it sentinel-cc bash

FROM fedora:41

LABEL maintainer="sentinel-cc"
LABEL description="Sentinel-CC: Compile-time Code Contracts with eBPF Enforcement"
LABEL version="4.5.0"

# System dependencies
RUN dnf install -y --setopt=install_weak_deps=False \
      clang llvm lld \
      bpftool libbpf-devel elfutils-libelf-devel \
      openssl-devel keyutils-libs-devel \
      cmake make \
      sqlite-devel libseccomp-devel \
      kernel-headers \
      wrk redis \
      python3 python3-pip \
      git diffutils procps-ng iproute \
    && dnf clean all

# BTF support (needed for CO-RE)
RUN if [ ! -f /sys/kernel/btf/vmlinux ]; then \
      echo "WARNING: BTF not available in container, BPF programs won't load at runtime"; \
    fi

WORKDIR /sentinel-cc
COPY . .

# Generate vmlinux.h if missing from host BTF
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
      bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
    fi

# Build everything
RUN make clean 2>/dev/null || true
RUN make -j$(nproc) 2>&1 | tail -20

# Build evaluation harnesses
RUN cc -O2 benchmarks/sqlite_bench.c -lsqlite3 -o benchmarks/sqlite_bench 2>/dev/null || true
RUN cc -O2 eval/landlock_harness.c -o eval/landlock_harness 2>/dev/null || true
RUN if pkg-config --exists libseccomp 2>/dev/null; then \
      cc -O2 eval/seccomp_harness.c -lseccomp -o eval/seccomp_harness; \
    fi 2>/dev/null || true

# Generate signing keys for testing
RUN openssl genpkey -algorithm ed25519 -out priv.pem 2>/dev/null && \
    openssl pkey -in priv.pem -pubout -out pub.pem 2>/dev/null || true

# Sign test binaries
RUN for bin in victim victim_phase2 victim_cfi victim_threaded; do \
      if [ -x "./$bin" ]; then \
        ./sign_tool "./$bin" priv.pem 2>/dev/null || true; \
      fi; \
    done

# Make scripts executable
RUN chmod +x benchmark.sh benchmarks/macro_bench.sh eval/comparative.sh 2>/dev/null || true

# Default: run microbenchmark (requires --privileged for BPF)
CMD ["bash", "-c", "echo 'Sentinel-CC Artifact Container' && echo 'Run: make test, ./benchmark.sh, or bash for interactive use' && bash"]
