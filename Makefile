# Sentinel-CC Master Makefile
# Supports: Build, Sign, Test, Clean
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')
VERSION := 4.5.0

# --- Directories ---
SRC_KERNEL  := src/kernel
SRC_RUNTIME := src/runtime
SRC_COMPILER:= src/compiler
SRC_COMMON  := src/common
TESTS       := tests

# --- Directories ---
SRC_CLI     := src/cli

# --- Targets ---
all: victim victim_phase2 victim_cfi victim_threaded victim_fork loader sentinel-dump sentinel-tui scc

# 0. Prerequisites
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 1. Build Compiler Pass
$(SRC_COMPILER)/build/SentinelPass.so:
	mkdir -p $(SRC_COMPILER)/build
	cd $(SRC_COMPILER)/build && cmake .. && make

# 2. Build Signing Tool
sign_tool: $(SRC_RUNTIME)/sign_tool.c
	$(CC) -O2 -Wall -Wextra $(SRC_RUNTIME)/sign_tool.c -lelf -lcrypto -o sign_tool

# 3. Generate Keys
keys:
	@if [ ! -f priv.pem ]; then \
		echo "[Keys] Generating Ed25519 Keypair..."; \
		openssl genpkey -algorithm Ed25519 -out priv.pem; \
		openssl pkey -in priv.pem -pubout -out pub.pem; \
	fi

install-keys: keys
	@echo "[Keys] Loading public key into session keyring..."
	@keyctl add user sentinel:pubkey "$$(cat pub.pem)" @s > /dev/null 2>&1 || true
	@kid=$$(keyctl search @s user sentinel:pubkey 2>/dev/null); \
	 if [ -n "$$kid" ]; then keyctl setperm "$$kid" 0x3f3f3f3f 2>/dev/null || true; fi

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

# 4e. Phase 3: Fork Tracking Test
victim_fork: $(TESTS)/victim_fork.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/victim_fork.c -o victim_fork
	./sign_tool victim_fork priv.pem

# --- Red Team Attack Binaries ---
ATTACK_BINS := attack_shellcode attack_rop attack_wxorx attack_hidden_syscall attack_ptrace \
               attack_memfd attack_vm_writev attack_seccomp attack_sendmsg attack_dup2

attack_shellcode: $(TESTS)/attack_shellcode.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_shellcode.c -o attack_shellcode
	./sign_tool attack_shellcode priv.pem

attack_rop: $(TESTS)/attack_rop.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -g -O0 -no-pie $(TESTS)/attack_rop.c -o attack_rop
	./sign_tool attack_rop priv.pem

attack_wxorx: $(TESTS)/attack_wxorx.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_wxorx.c -o attack_wxorx
	./sign_tool attack_wxorx priv.pem

attack_hidden_syscall: $(TESTS)/attack_hidden_syscall.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_hidden_syscall.c -o attack_hidden_syscall
	./sign_tool attack_hidden_syscall priv.pem

attack_ptrace: $(TESTS)/attack_ptrace.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_ptrace.c -o attack_ptrace
	./sign_tool attack_ptrace priv.pem

attack_memfd: $(TESTS)/attack_memfd.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_memfd.c -o attack_memfd
	./sign_tool attack_memfd priv.pem

attack_vm_writev: $(TESTS)/attack_vm_writev.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_vm_writev.c -o attack_vm_writev
	./sign_tool attack_vm_writev priv.pem

attack_seccomp: $(TESTS)/attack_seccomp.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_seccomp.c -o attack_seccomp
	./sign_tool attack_seccomp priv.pem

attack_sendmsg: $(TESTS)/attack_sendmsg.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_sendmsg.c -o attack_sendmsg
	./sign_tool attack_sendmsg priv.pem

attack_dup2: $(TESTS)/attack_dup2.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -O2 $(TESTS)/attack_dup2.c -o attack_dup2
	./sign_tool attack_dup2 priv.pem

attacks: $(ATTACK_BINS)

# --- Benchmark ---
victim_bench: $(TESTS)/victim_bench.c $(SRC_COMPILER)/build/SentinelPass.so sign_tool keys
	$(CLANG) -fpass-plugin=$(SRC_COMPILER)/build/SentinelPass.so -fno-inline -O2 $(TESTS)/victim_bench.c -o victim_bench
	./sign_tool victim_bench priv.pem

bench: victim_bench loader
	chmod +x benchmark.sh
	sudo ./benchmark.sh

# 5. Build Kernel Enforcer
# -nostdinc avoids system bpf headers that may lack vmlinux.h types on Ubuntu
# Then re-add clang builtins (stddef.h) and libbpf headers via -idirafter
CLANG_BPF_FLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -nostdinc \
	-isystem $(shell $(CLANG) -print-resource-dir)/include \
	-I. -I/usr/include
sentinel.bpf.o: $(SRC_KERNEL)/sentinel.bpf.c $(SRC_COMMON)/sentinel_shared.h vmlinux.h
	$(CLANG) $(CLANG_BPF_FLAGS) -c $(SRC_KERNEL)/sentinel.bpf.c -o sentinel.bpf.o

sentinel.skel.h: sentinel.bpf.o
	$(BPFTOOL) gen skeleton sentinel.bpf.o > sentinel.skel.h

# 6. Build Loader
loader: $(SRC_RUNTIME)/loader.c $(SRC_COMMON)/sentinel_shared.h sentinel.skel.h
	$(CLANG) -g -O2 -Wall -Wextra -I. $(SRC_RUNTIME)/loader.c -lbpf -lelf -lcrypto -lkeyutils -o loader

# 7. Build Policy Inspector
sentinel-dump: $(SRC_RUNTIME)/sentinel_dump.c
	$(CC) -O2 -Wall -Wextra $(SRC_RUNTIME)/sentinel_dump.c -lelf -o sentinel-dump

# 8. Build TUI Dashboard
sentinel-tui: $(SRC_RUNTIME)/sentinel_tui.c
	$(CC) -O2 -Wall -Wextra $(SRC_RUNTIME)/sentinel_tui.c -o sentinel-tui

# 9. Install scc CLI
scc: $(SRC_CLI)/scc.sh
	cp $(SRC_CLI)/scc.sh scc
	chmod +x scc

# --- Execution ---
run: all
	sudo ./loader ./victim

run-audit: all
	sudo ./loader --audit ./victim

run-phase2: all
	sudo ./loader --audit ./victim_phase2

run-cfi: all
	sudo ./loader --audit ./victim_cfi

run-threaded: all
	sudo ./loader --audit ./victim_threaded

run-fork: all
	sudo ./loader --audit ./victim_fork

# --- Testing ---
test: all
	sudo $(TESTS)/run_all.sh

red-team: all attacks
	sudo $(TESTS)/red_team.sh

# --- Utility ---
version:
	@echo "Sentinel-CC v$(VERSION)"

help:
	@echo "Sentinel-CC Build System v$(VERSION)"
	@echo ""
	@echo "Targets:"
	@echo "  all            Build everything (default)"
	@echo "  loader         Build the runtime loader"
	@echo "  sign_tool      Build the signing tool"
	@echo "  victim         Build & sign Phase 1 test binary"
	@echo "  victim_phase2  Build & sign Phase 2 test binary"
	@echo "  victim_cfi     Build & sign CFI test binary"
	@echo "  victim_threaded Build & sign threading test binary"
	@echo "  victim_fork    Build & sign fork-tracking test binary"
	@echo "  run            Build all and run Phase 1 test"
	@echo "  run-audit      Run Phase 1 with audit logging"
	@echo "  run-phase2     Run Phase 2 with audit logging"
	@echo "  run-cfi        Run CFI test with audit logging"
	@echo "  run-threaded   Run threading test with audit logging"
	@echo "  test           Run automated test suite (requires sudo)"
	@echo "  attacks        Build all red-team attack binaries"
	@echo "  red-team       Build & run adversarial attack suite (requires sudo)"
	@echo "  victim_bench   Build & sign the benchmark binary"
	@echo "  bench          Run latency benchmark (requires sudo)"
	@echo "  install-keys   Load public key into kernel keyring (requires sudo)"
	@echo "  keys           Generate Ed25519 keypair"
	@echo "  sentinel-dump  Build the policy inspector tool"
	@echo "  sentinel-tui   Build the terminal dashboard"
	@echo "  scc            Build the unified CLI tool"
	@echo "  install        Install all tools system-wide (loader, sign, dump, tui, scc)"
	@echo "  install-man    Install man pages to /usr/local/share/man/man1"
	@echo "  install-systemd  Install systemd template service unit"
	@echo "  key-rotate     Generate new keypair, re-sign binaries, revoke old key"
	@echo "  key-revoke     Add current key fingerprint to revocation list"
	@echo "  clean          Remove all build artifacts"
	@echo "  help           Show this help"

# --- Install ---
PREFIX ?= /usr/local
SYSCONFDIR ?= /etc/sentinel

install: loader sign_tool sentinel-dump sentinel-tui scc
	install -D -m 755 loader $(DESTDIR)$(PREFIX)/bin/sentinel-loader
	install -D -m 755 sign_tool $(DESTDIR)$(PREFIX)/bin/sentinel-sign
	install -D -m 755 sentinel-dump $(DESTDIR)$(PREFIX)/bin/sentinel-dump
	install -D -m 755 sentinel-tui $(DESTDIR)$(PREFIX)/bin/sentinel-tui
	install -D -m 755 scc $(DESTDIR)$(PREFIX)/bin/scc
	install -d $(DESTDIR)$(SYSCONFDIR)
	@if [ -f pub.pem ]; then \
		install -m 644 pub.pem $(DESTDIR)$(SYSCONFDIR)/pub.pem; \
	fi
	@echo "[Install] Installed to $(DESTDIR)$(PREFIX)/bin/"

install-systemd:
	install -D -m 644 etc/sentinel@.service $(DESTDIR)/etc/systemd/system/sentinel@.service
	@echo "[Install] Systemd template installed. Enable with: systemctl enable sentinel@<binary>"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/sentinel-loader
	rm -f $(DESTDIR)$(PREFIX)/bin/sentinel-sign
	rm -f $(DESTDIR)$(PREFIX)/bin/sentinel-dump
	rm -f $(DESTDIR)$(PREFIX)/bin/sentinel-tui
	rm -f $(DESTDIR)$(PREFIX)/bin/scc
	rm -f $(DESTDIR)/etc/systemd/system/sentinel@.service
	@echo "[Uninstall] Removed from $(DESTDIR)$(PREFIX)/bin/"

install-man:
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 man/sentinel-loader.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 man/sentinel-sign.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 man/sentinel-dump.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 man/sentinel-tui.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 man/scc.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	@echo "[Install] Man pages installed to $(DESTDIR)$(PREFIX)/share/man/man1/"

# --- Key Rotation ---
key-revoke: keys
	@echo "[KeyRotate] Computing fingerprint of current public key..."
	@openssl pkey -pubin -in pub.pem -outform DER 2>/dev/null | \
		openssl dgst -sha256 -r | cut -d' ' -f1 >> /etc/sentinel/revoked_keys 2>/dev/null || \
		(mkdir -p /etc/sentinel && openssl pkey -pubin -in pub.pem -outform DER 2>/dev/null | \
		openssl dgst -sha256 -r | cut -d' ' -f1 >> /etc/sentinel/revoked_keys)
	@echo "[KeyRotate] Current key added to revocation list."

key-rotate: key-revoke
	@echo "[KeyRotate] Generating new Ed25519 keypair..."
	rm -f priv.pem pub.pem
	openssl genpkey -algorithm Ed25519 -out priv.pem
	openssl pkey -in priv.pem -pubout -out pub.pem
	@echo "[KeyRotate] Re-signing all binaries..."
	@for bin in victim victim_phase2 victim_cfi victim_threaded victim_fork $(ATTACK_BINS); do \
		if [ -f $$bin ]; then ./sign_tool $$bin priv.pem; fi; \
	done
	@echo "[KeyRotate] Updating keyring..."
	keyctl add user sentinel:pubkey "$$(cat pub.pem)" @s > /dev/null 2>&1 || true
	@echo "[KeyRotate] Key rotation complete."

clean:
	rm -f victim victim_phase2 victim_cfi victim_threaded victim_fork loader sign_tool sentinel-dump sentinel-tui scc
	rm -f sentinel.bpf.o sentinel.skel.h priv.pem pub.pem vmlinux.h
	rm -f victim_tampered victim_bench
	rm -f $(ATTACK_BINS)
	rm -rf $(SRC_COMPILER)/build

.PHONY: all attacks bench run run-audit run-phase2 run-cfi run-threaded run-fork test red-team keys install-keys install install-man install-systemd uninstall key-rotate key-revoke clean help version scc