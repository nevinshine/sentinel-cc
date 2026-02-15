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
all: victim loader

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

# 4. Build Victim (Signed)
victim: $(TESTS)/victim.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 -fPIE -pie $(TESTS)/victim.c -o victim
	./sign_tool victim priv.pem

# 4b. Phase 2 Victim (Dynamic Linked - Uses Libc)
victim_phase2: $(TESTS)/victim_phase2.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	# Compile as standard Dynamic Executable (uses libc.so)
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/victim_phase2.c -o victim_phase2
	./sign_tool victim_phase2 priv.pem

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
	rm -f victim victim_phase2 loader sign_tool sentinel.bpf.o sentinel.skel.h priv.pem pub.pem vmlinux.h
	rm -rf $(SRC_COMPILER)/build