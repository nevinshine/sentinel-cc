# Sentinel-CC Master Makefile (Fedora Compatible)
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')

# --- Directories ---
SRC_KERNEL  := src/kernel
SRC_RUNTIME := src/runtime
SRC_COMPILER:= src/compiler
TESTS       := tests

# --- Targets ---
all: victim victim_phase2 victim_cfi victim_threaded loader

# 0. Prerequisites
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 1. Build Compiler Pass
$(SRC_COMPILER)/build/SentinelPass.so:
	mkdir -p $(SRC_COMPILER)/build
	cd $(SRC_COMPILER)/build && cmake .. && make

# 2. Build Signing Tool
sign_tool: $(SRC_RUNTIME)/sign_tool.c
	$(CC) -O2 $(SRC_RUNTIME)/sign_tool.c -lelf -lcrypto -o sign_tool

# 3. Generate Keys
keys:
	@if [ ! -f priv.pem ]; then \
		echo "[Keys] Generating RSA-2048 Keypair..."; \
		openssl genrsa -out priv.pem 2048; \
		openssl rsa -in priv.pem -pubout -out pub.pem; \
	fi

# 4. Build Victim (Signed, Static Inline Syscalls)
victim: $(TESTS)/victim.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 -fPIE -pie $(TESTS)/victim.c -o victim
	./sign_tool victim priv.pem

# 4b. Phase 2 Victim (Dynamic Linked - Uses Libc)
victim_phase2: $(TESTS)/victim_phase2.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/victim_phase2.c -o victim_phase2
	./sign_tool victim_phase2 priv.pem

# 4c. Phase 2.2: CFI Victim (Deep CFI Test)
victim_cfi: $(TESTS)/victim_cfi.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -g -O0 -no-pie $(TESTS)/victim_cfi.c -o victim_cfi
	./sign_tool victim_cfi priv.pem

# 4d. Phase 2.3: Threaded Victim (Multithreading Test)
victim_threaded: $(TESTS)/victim_threaded.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -g -O2 -pthread $(TESTS)/victim_threaded.c -o victim_threaded
	./sign_tool victim_threaded priv.pem

# 5. Build Kernel Enforcer
sentinel.bpf.o: $(SRC_KERNEL)/sentinel.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $(SRC_KERNEL)/sentinel.bpf.c -o sentinel.bpf.o

sentinel.skel.h: sentinel.bpf.o
	$(BPFTOOL) gen skeleton sentinel.bpf.o > sentinel.skel.h

# 6. Build Loader (Requires -lkeyutils for Phase 1.4)
loader: $(SRC_RUNTIME)/loader.c sentinel.skel.h
	$(CLANG) -g -O2 -I. $(SRC_RUNTIME)/loader.c -lbpf -lelf -lcrypto -lkeyutils -o loader

# --- Execution ---
run: all
	sudo ./loader ./victim

clean:
	rm -f victim victim_phase2 victim_cfi victim_threaded loader sign_tool sentinel.bpf.o sentinel.skel.h priv.pem pub.pem vmlinux.h
	rm -rf $(SRC_COMPILER)/build