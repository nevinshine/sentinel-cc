CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')

all: victim loader

# 1. Build Sentinel Pass (Helper)
llvm-pass/build/SentinelPass.so:
	mkdir -p llvm-pass/build
	cd llvm-pass/build && cmake .. && make

# 2. Build Signing Tool (C Toolchain)
sign_tool: sign_tool.c
	$(CC) -O2 sign_tool.c -lelf -lcrypto -o sign_tool

# 3. Generate RSA Keypair
keys:
	@if [ ! -f priv.pem ]; then \
		echo "[Keys] Generating RSA-2048 Keypair..."; \
		openssl genrsa -out priv.pem 2048; \
		openssl rsa -in priv.pem -pubout -out pub.pem; \
	fi

# 4. Build Victim using the Sentinel Pass (PCC) AND Sign it
victim: victim.c llvm-pass/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=llvm-pass/build/SentinelPass.so -O2 -fPIE -pie victim.c -o victim
	./sign_tool victim priv.pem

# 5. Build BPF Enforcer (Phase 3 Logic)
sentinel.bpf.o: sentinel.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c sentinel.bpf.c -o sentinel.bpf.o

# 6. Generate BPF Skeleton
sentinel.skel.h: sentinel.bpf.o
	$(BPFTOOL) gen skeleton sentinel.bpf.o > sentinel.skel.h

# 7. Build Loader (with libelf and libcrypto integration)
loader: loader.c sentinel.skel.h
	$(CLANG) -g -O2 loader.c -lbpf -lelf -lcrypto -o loader

run: all
	sudo ./loader ./victim

clean:
	rm -f victim loader sentinel.bpf.o sentinel.skel.h
