# Sentinel-CC Master Makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')

# Directories
SRC_KERNEL  := src/kernel
SRC_RUNTIME := src/runtime
SRC_COMPILER:= src/compiler
TESTS       := tests

# Targets
all: victim loader

# --- 0. Prerequisites ---
# Generate vmlinux.h if missing
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# --- 1. Build Compiler Pass ---
$(SRC_COMPILER)/build/SentinelPass.so:
	mkdir -p $(SRC_COMPILER)/build
	cd $(SRC_COMPILER)/build && cmake .. && make

# --- 2. Build Signing Tool ---
sign_tool: $(SRC_RUNTIME)/sign_tool.c
	$(CC) -O2 $(SRC_RUNTIME)/sign_tool.c -lelf -lcrypto -o sign_tool

# --- 3. Build Victim (Signed) ---
keys:
	@if [ ! -f priv.pem ]; then \
		echo "[Keys] Generating RSA-2048 Keypair..."; \
		openssl genrsa -out priv.pem 2048; \
		openssl rsa -in priv.pem -pubout -out pub.pem; \
	fi

victim: $(TESTS)/victim.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 -fPIE -pie $(TESTS)/victim.c -o victim
	./sign_tool victim priv.pem

# --- 4. Build Kernel Enforcer ---
sentinel.bpf.o: $(SRC_KERNEL)/sentinel.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $(SRC_KERNEL)/sentinel.bpf.c -o sentinel.bpf.o

sentinel.skel.h: sentinel.bpf.o
	$(BPFTOOL) gen skeleton sentinel.bpf.o > sentinel.skel.h

# --- 5. Build Loader ---
# Added -I. to find sentinel.skel.h in root
loader: $(SRC_RUNTIME)/loader.c sentinel.skel.h
	$(CLANG) -g -O2 -I. $(SRC_RUNTIME)/loader.c -lbpf -lelf -lcrypto -lkeyutils -o loader

# --- Execution ---
run: all
	sudo ./loader ./victim

# --- Clean ---
clean:
	rm -f victim loader sign_tool sentinel.bpf.o sentinel.skel.h priv.pem pub.pem vmlinux.h
	rm -rf $(SRC_COMPILER)/build
