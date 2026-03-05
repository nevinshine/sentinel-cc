#!/bin/bash
# benchmark.sh — Sentinel-CC Syscall Latency Microbenchmark
# Measures the per-syscall overhead of eBPF enforcement by comparing
# native (unprotected) vs Sentinel-enforced write(2) latency.
#
# Usage:  sudo ./benchmark.sh [iterations]
# Output: side-by-side comparison with computed overhead.

set -u

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

TMPOUT=$(mktemp /tmp/sentinel_bench.XXXXXX)
trap 'rm -f "$TMPOUT"' EXIT

# ── Helpers ──────────────────────────────────────────────────────────

die()   { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }

setup_keyring() {
  if [ ! -f pub.pem ]; then
    die "pub.pem not found. Run 'make' first."
  fi
  # Always refresh: make clean && make regenerates keys
  keyctl add user sentinel:pubkey "$(cat pub.pem)" @s > /dev/null 2>&1 || true
  local kid
  kid=$(keyctl search @s user sentinel:pubkey 2>/dev/null) || true
  if [ -n "$kid" ]; then
    keyctl setperm "$kid" 0x3f3f3f3f 2>/dev/null || true
  else
    die "Could not load key into session keyring."
  fi
}

extract_avg() {
  # Parse BENCH_AVG_NS=<value> from mixed loader+child output
  grep -m1 'BENCH_AVG_NS=' "$1" | cut -d= -f2
}

extract_total() {
  grep -m1 'BENCH_TOTAL_NS=' "$1" | cut -d= -f2
}

extract_iters() {
  grep -m1 'BENCH_ITERATIONS=' "$1" | cut -d= -f2
}

# ── Preconditions ────────────────────────────────────────────────────

[[ -x ./victim_bench ]] || die "victim_bench not found. Run: make victim_bench"
[[ -x ./loader ]]       || die "loader not found. Run: make"
[[ $(id -u) -eq 0 ]]    || die "Must run as root (sudo ./benchmark.sh)"

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Sentinel-CC Syscall Latency Benchmark${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""

# ── Phase 1: Baseline (Native) ──────────────────────────────────────

info "Phase 1: Native execution (no enforcement)"
./victim_bench > "$TMPOUT" 2>/dev/null </dev/null

NATIVE_AVG=$(extract_avg "$TMPOUT")
NATIVE_TOTAL=$(extract_total "$TMPOUT")
NATIVE_ITERS=$(extract_iters "$TMPOUT")

if [[ -z "$NATIVE_AVG" ]]; then
  die "Failed to parse native benchmark output"
fi

ok "Native:   ${BOLD}${NATIVE_AVG} ns/syscall${NC}  (${NATIVE_ITERS} iterations, ${NATIVE_TOTAL} ns total)"

# ── Phase 2: Enforced (Sentinel-CC) ─────────────────────────────────

info "Phase 2: Sentinel-CC enforced execution"
setup_keyring
./loader ./victim_bench > "$TMPOUT" 2>&1 </dev/null || true

ENFORCED_AVG=$(extract_avg "$TMPOUT")
ENFORCED_TOTAL=$(extract_total "$TMPOUT")

if [[ -z "$ENFORCED_AVG" ]]; then
  echo -e "${RED}[FAIL]${NC} Could not parse enforced benchmark output." >&2
  echo -e "${RED}── Loader output ──${NC}" >&2
  cat "$TMPOUT" >&2
  echo -e "${RED}── end ──${NC}" >&2
  exit 1
fi

ok "Enforced: ${BOLD}${ENFORCED_AVG} ns/syscall${NC}  (${NATIVE_ITERS} iterations, ${ENFORCED_TOTAL} ns total)"

# ── Phase 3: Compute Overhead ───────────────────────────────────────

OVERHEAD=$((ENFORCED_AVG - NATIVE_AVG))
if [[ "$NATIVE_AVG" -gt 0 ]]; then
  # Integer-safe percentage: (overhead * 10000) / native, then format
  PCT_X100=$(( (OVERHEAD * 10000) / NATIVE_AVG ))
  PCT_INT=$((PCT_X100 / 100))
  PCT_FRAC=$((PCT_X100 % 100))
  if [[ $PCT_FRAC -lt 0 ]]; then PCT_FRAC=$((-PCT_FRAC)); fi
  PCT="${PCT_INT}.$(printf '%02d' $PCT_FRAC)%"
else
  PCT="N/A"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "  Native latency:     ${GREEN}${NATIVE_AVG} ns${NC}"
echo -e "  Enforced latency:   ${YELLOW}${ENFORCED_AVG} ns${NC}"
echo -e "  eBPF overhead:      ${BOLD}${OVERHEAD} ns/syscall${NC} (${PCT})"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""

if [[ "$OVERHEAD" -le 500 ]]; then
  ok "Overhead is within wire-speed threshold (< 500 ns)."
else
  echo -e "${YELLOW}[!]${NC} Overhead exceeds 500 ns — check system load."
fi

# ── Phase 3: Attack Surface Reduction ────────────────────────────────

echo ""
info "Phase 3: Attack surface reduction (per-app libc filtering)"

# Run victim_phase2 under the loader with --audit to capture call-graph stats
if [[ -x ./victim_phase2 ]]; then
  ./loader --audit ./victim_phase2 > "$TMPOUT" 2>&1 </dev/null || true

  REDUCTION=$(grep -o '[0-9.]*% reduction' "$TMPOUT" | head -1)
  SITES_LINE=$(grep 'syscall sites' "$TMPOUT" | head -1)
  REACHABLE=$(grep -oP '\d+ reachable functions' "$TMPOUT" | head -1)

  if [[ -n "$REDUCTION" ]]; then
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}Per-App Libc Filtering Results${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    if [[ -n "$SITES_LINE" ]]; then
      echo -e "  ${GREEN}$SITES_LINE${NC}"
    fi
    if [[ -n "$REACHABLE" ]]; then
      echo -e "  Call-graph BFS:  ${BOLD}$REACHABLE${NC}"
    fi
    echo -e "  Attack surface:  ${BOLD}$REDUCTION${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo ""
    ok "Per-app filtering measured successfully."
  else
    echo -e "${YELLOW}[!]${NC} Could not parse attack-surface reduction from loader output."
    echo -e "${YELLOW}    Ensure victim_phase2 has .sentinel_imports section.${NC}"
  fi
else
  echo -e "${YELLOW}[!]${NC} victim_phase2 not found — skipping attack surface measurement."
  echo -e "${YELLOW}    Run: make victim_phase2${NC}"
fi
