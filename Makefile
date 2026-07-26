# Sentinel-CC Research Makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')
VERSION := 4.5.0-research

# --- Directories ---
SRC_KERNEL  := src/kernel
SRC_RUNTIME := src/runtime
SRC_COMPILER:= src/compiler
SRC_COMMON  := src/common
TESTS       := tests

# --- Targets ---
all: victim victim_phase2 loader sentinel-dump

# 0. Prerequisites
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 1. Build Compiler Pass
$(SRC_COMPILER)/build/SentinelPass.so:
	mkdir -p $(SRC_COMPILER)/build
	cd $(SRC_COMPILER)/build && cmake .. && make

# 2. Build Victim (Phase 1: Static Inline Syscalls)
victim: $(TESTS)/victim.c $(SRC_COMPILER)/build/SentinelPass.so
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 -fPIE -pie $(TESTS)/victim.c -o victim

# 3. Build Victim (Phase 2: Dynamic Linked - Uses Libc)
victim_phase2: $(TESTS)/victim_phase2.c $(SRC_COMPILER)/build/SentinelPass.so
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/victim_phase2.c -o victim_phase2

# 4. Build Kernel Enforcer
CLANG_BPF_FLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -nostdinc \
	-isystem $(shell $(CLANG) -print-resource-dir)/include \
	-I. -I/usr/include
sentinel.bpf.o: $(SRC_KERNEL)/sentinel.bpf.c $(SRC_COMMON)/sentinel_shared.h vmlinux.h
	$(CLANG) $(CLANG_BPF_FLAGS) -c $(SRC_KERNEL)/sentinel.bpf.c -o sentinel.bpf.o

sentinel.skel.h: sentinel.bpf.o
	$(BPFTOOL) gen skeleton sentinel.bpf.o > sentinel.skel.h

# 5. Build Loader (Pruned - no crypto/keyutils)
loader: $(SRC_RUNTIME)/loader.c $(SRC_COMMON)/sentinel_shared.h sentinel.skel.h
	$(CLANG) -g -O2 -Wall -Wextra -I. $(SRC_RUNTIME)/loader.c -lbpf -lelf -o loader

# 6. Build Policy Inspector
sentinel-dump: $(SRC_RUNTIME)/sentinel_dump.c
	$(CC) -O2 -Wall -Wextra $(SRC_RUNTIME)/sentinel_dump.c -lelf -o sentinel-dump

# --- Execution ---
run: all
	sudo ./loader ./victim

run-phase2: all
	sudo ./loader --audit ./victim_phase2

clean:
	rm -f victim victim_phase2 loader sentinel-dump
	rm -f sentinel.bpf.o sentinel.skel.h vmlinux.h
	rm -rf $(SRC_COMPILER)/build

.PHONY: all run run-phase2 clean