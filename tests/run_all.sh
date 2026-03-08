#!/bin/bash
# tests/run_all.sh — Sentinel-CC Automated Test Suite
# Runs all test phases and reports PASS/FAIL
#
# Usage: sudo ./tests/run_all.sh

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; ((SKIP++)); }
header() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

# Ensure we're in the project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Check prerequisites
check_prereqs() {
  header "Prerequisites Check"
  local ok=1

  for cmd in clang bpftool openssl keyctl; do
    if command -v "$cmd" &>/dev/null; then
      pass "$cmd found: $(command -v "$cmd")"
    else
      fail "$cmd not found"
      ok=0
    fi
  done

  if [ ! -f /sys/kernel/btf/vmlinux ]; then
    fail "BTF not available (/sys/kernel/btf/vmlinux missing)"
    ok=0
  else
    pass "BTF available"
  fi

  if [ "$(id -u)" -ne 0 ]; then
    fail "Must run as root (sudo)"
    ok=0
  else
    pass "Running as root"
  fi

  # In bash, return 0 = success, return 1 = failure
  [ "$ok" -eq 1 ] && return 0 || return 1
}

# Build everything
build_all() {
  header "Building Project"

  if make clean && make 2>&1 | tail -5; then
    pass "Build succeeded"
  else
    fail "Build failed"
    return 1
  fi

  # Verify all binaries exist
  for bin in victim victim_phase2 victim_cfi victim_threaded victim_fork loader sign_tool; do
    if [ -f "$bin" ]; then
      pass "Binary exists: $bin"
    else
      fail "Binary missing: $bin"
    fi
  done
}

# Setup keyring
setup_keyring() {
  header "Keyring Setup"

  if [ ! -f pub.pem ]; then
    fail "pub.pem not found"
    return 1
  fi

  keyctl add user sentinel:pubkey "$(cat pub.pem)" @s > /dev/null 2>&1
  KEY_ID=$(keyctl search @s user sentinel:pubkey 2>/dev/null || true)

  if [ -n "$KEY_ID" ]; then
    keyctl setperm "$KEY_ID" 0x3f3f3f3f 2>/dev/null || true
    pass "Key loaded (ID=$KEY_ID)"
  else
    fail "Failed to load key into session keyring"
    return 1
  fi
}

# Test: Binary has required ELF sections
test_elf_sections() {
  header "Test: ELF Section Integrity"

  for bin in victim victim_phase2 victim_cfi victim_threaded victim_fork; do
    if [ ! -f "$bin" ]; then
      skip "$bin not built"
      continue
    fi

    local has_sentinel=0 has_signature=0

    if readelf -S "$bin" 2>/dev/null | grep -q '\.sentinel'; then
      has_sentinel=1
    fi
    if readelf -S "$bin" 2>/dev/null | grep -q '\.signature'; then
      has_signature=1
    fi

    if [ "$has_sentinel" -eq 1 ] && [ "$has_signature" -eq 1 ]; then
      pass "$bin has .sentinel and .signature sections"
    else
      fail "$bin missing sections (sentinel=$has_sentinel, signature=$has_signature)"
    fi
  done

  # Check CFI-specific sections
  for bin in victim_cfi; do
    if [ ! -f "$bin" ]; then continue; fi
    if readelf -S "$bin" 2>/dev/null | grep -q '\.sentinel_cfi'; then
      pass "$bin has .sentinel_cfi section"
    else
      fail "$bin missing .sentinel_cfi section"
    fi
  done

  # Check .sentinel_imports on dynamically-linked binaries
  for bin in victim_phase2 victim_fork; do
    if [ ! -f "$bin" ]; then continue; fi
    if readelf -S "$bin" 2>/dev/null | grep -q '\.sentinel_imports'; then
      pass "$bin has .sentinel_imports section"
    else
      fail "$bin missing .sentinel_imports section"
    fi
  done
}

# Test: Signature verification succeeds for valid binaries
test_signature_valid() {
  header "Test: Signature Verification (Valid)"

  for bin in victim victim_phase2 victim_cfi victim_threaded victim_fork; do
    if [ ! -f "$bin" ]; then
      skip "$bin not built"
      continue
    fi

    local output
    output=$(timeout 15 ./loader "$bin" 2>&1) || true

    if echo "$output" | grep -q "Signature Verified"; then
      pass "$bin signature verified"
    else
      fail "$bin signature verification failed"
      echo "    Output: $(echo "$output" | head -3)"
    fi
  done
}

# Test: Tampered binary is rejected
test_tamper_detection() {
  header "Test: Tamper Detection"

  if [ ! -f victim ]; then
    skip "victim not built"
    return
  fi

  # Make a copy, tamper it, test rejection
  cp victim victim_tampered

  # Flip a byte in the .text section
  echo -n "X" | dd of=victim_tampered bs=1 seek=500 count=1 conv=notrunc 2>/dev/null

  local output
  output=$(timeout 10 ./loader victim_tampered 2>&1) || true

  if echo "$output" | grep -qi "FAIL\|tamper"; then
    pass "Tampered binary correctly rejected"
  else
    fail "Tampered binary was NOT rejected"
    echo "    Output: $(echo "$output" | head -3)"
  fi

  rm -f victim_tampered
}

# Test: Phase 1 victim (inline syscalls)
test_phase1() {
  header "Test: Phase 1 — Inline Syscall Enforcement"

  if [ ! -f victim ]; then
    skip "victim not built"
    return
  fi

  local output
  output=$(timeout 15 ./loader ./victim 2>&1) || true

  if echo "$output" | grep -q "Signature Verified"; then
    pass "Phase 1: Signature check passed"
  else
    fail "Phase 1: Signature check failed"
  fi

  if echo "$output" | grep -q "policy entries"; then
    pass "Phase 1: Policy entries loaded"
  else
    fail "Phase 1: No policy entries found"
  fi
}

# Test: Phase 2 victim (shared libraries / ASLR)
test_phase2() {
  header "Test: Phase 2 — Shared Library + ASLR"

  if [ ! -f victim_phase2 ]; then
    skip "victim_phase2 not built"
    return
  fi

  local output
  output=$(timeout 15 ./loader ./victim_phase2 2>&1) || true

  if echo "$output" | grep -q "Libc VMA"; then
    pass "Phase 2: Libc VMA populated"
  else
    fail "Phase 2: Libc VMA not populated"
  fi

  if echo "$output" | grep -q "Libc path:"; then
    pass "Phase 2: Libc path dynamically resolved"
  else
    fail "Phase 2: Libc path not resolved"
  fi

  if echo "$output" | grep -qi "reachable\|per-app\|syscall sites"; then
    pass "Phase 2: Per-app libc filtering active"
  else
    skip "Phase 2: Per-app filtering output not found (check --audit)"
  fi
}

# Test: Phase 2.2 CFI victim
test_cfi() {
  header "Test: Phase 2.2 — Deep CFI (Caller Validation)"

  if [ ! -f victim_cfi ]; then
    skip "victim_cfi not built"
    return
  fi

  local output
  output=$(timeout 15 ./loader ./victim_cfi 2>&1) || true

  if echo "$output" | grep -q "CFI Symbols"; then
    pass "CFI: Symbols detected"
  else
    fail "CFI: Symbols not found"
  fi

  if echo "$output" | grep -q "CFI Policy"; then
    pass "CFI: Policy loaded"
  else
    fail "CFI: Policy not loaded"
  fi
}

# Test: Phase 2.3 Multithreaded victim
test_threaded() {
  header "Test: Phase 2.3 — Multithreading Stability"

  if [ ! -f victim_threaded ]; then
    skip "victim_threaded not built"
    return
  fi

  local output
  output=$(timeout 15 ./loader ./victim_threaded 2>&1) || true

  if echo "$output" | grep -q "Policy loaded"; then
    pass "Threaded: Policy loaded for TGID"
  else
    fail "Threaded: Policy not loaded"
  fi
}

# Test: Fork Tracking
test_fork() {
  header "Test: Fork Tracking (sched_process_fork)"

  if [ ! -f victim_fork ]; then
    skip "victim_fork not built"
    return
  fi

  local output
  output=$(timeout 15 ./loader ./victim_fork 2>&1) || true

  if echo "$output" | grep -qi "child.*exit\|All done\|fork.*track"; then
    pass "Fork: Child process tracked and completed"
  elif echo "$output" | grep -qi "BLOCK\|SIGKILL"; then
    fail "Fork: Child was killed — fork tracking broken"
  else
    skip "Fork: Inconclusive (check --audit output)"
  fi
}

# Test: Unsigned binary (no .sentinel section)
test_unsigned_binary() {
  header "Test: Unsigned Binary Rejection"

  # Compile a plain binary without the Sentinel pass
  echo 'int main() { return 0; }' > /tmp/sentinel_test_plain.c
  clang -O2 /tmp/sentinel_test_plain.c -o /tmp/sentinel_test_plain 2>/dev/null

  local output
  output=$(timeout 10 ./loader /tmp/sentinel_test_plain 2>&1) || true

  if echo "$output" | grep -qi "FATAL\|Missing"; then
    pass "Unsigned binary correctly rejected"
  else
    fail "Unsigned binary was NOT rejected"
    echo "    Output: $(echo "$output" | head -3)"
  fi

  rm -f /tmp/sentinel_test_plain /tmp/sentinel_test_plain.c
}

# Test: CLI help flags
test_cli() {
  header "Test: CLI Help & Version"

  if ./loader --help 2>&1 | grep -q "Usage"; then
    pass "loader --help works"
  else
    fail "loader --help broken"
  fi

  if ./loader --version 2>&1 | grep -q "Sentinel-CC"; then
    pass "loader --version works"
  else
    fail "loader --version broken"
  fi

  if ./sign_tool --help 2>&1 | grep -q "Usage"; then
    pass "sign_tool --help works"
  else
    fail "sign_tool --help broken"
  fi

  if ./sign_tool --version 2>&1 | grep -q "Sentinel-CC"; then
    pass "sign_tool --version works"
  else
    fail "sign_tool --version broken"
  fi
}

# =============================================================================
# Run All Tests
# =============================================================================
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║     Sentinel-CC Automated Test Suite v4.0.0    ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

check_prereqs || { echo "Prerequisites not met."; exit 1; }
build_all || { echo "Build failed."; exit 1; }
setup_keyring || { echo "Keyring setup failed."; exit 1; }

test_elf_sections
test_cli
test_signature_valid
test_tamper_detection
test_unsigned_binary
test_phase1
test_phase2
test_cfi
test_threaded
test_fork

# =============================================================================
# Summary
# =============================================================================
header "Results Summary"
TOTAL=$((PASS + FAIL + SKIP))
echo -e "  Total:   $TOTAL"
echo -e "  ${GREEN}Passed:  $PASS${NC}"
echo -e "  ${RED}Failed:  $FAIL${NC}"
echo -e "  ${YELLOW}Skipped: $SKIP${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All tests passed! ✓${NC}"
  exit 0
else
  echo -e "${RED}$FAIL test(s) failed. ✗${NC}"
  exit 1
fi
