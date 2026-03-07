#!/bin/bash
# bench_full.sh — Comprehensive Sentinel-CC Benchmark Suite
# Produces structured metrics for documentation / research papers.
#
# Measures:
#   1. Per-syscall latency (getpid microbenchmark — pure kernel overhead)
#   2. I/O-heavy workload (write 1M lines to /dev/null)
#   3. File-open storm (open/close 100K files)
#   4. Context-switch rate under enforcement
#   5. Policy map scalability (entries vs lookup time)
#   6. Attack surface reduction (per-app libc filtering)
#
# Usage: sudo ./bench_full.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

info()  { echo -e ":: $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; }

RESULTS_FILE="/tmp/sentinel_bench_$(date +%Y%m%d_%H%M%S).json"

# ══════════════════════════════════════════════════════
header() {
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Sentinel-CC Comprehensive Benchmark Suite${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Kernel:     $(uname -r)"
    echo "  CPU:        $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo "  Cores:      $(nproc)"
    echo "  Date:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  Project:    $PROJECT_ROOT"
    echo ""
}

# ══════════════════════════════════════════════════════
# Phase 1: Syscall Latency Microbenchmark
# ══════════════════════════════════════════════════════
bench_latency() {
    info "Phase 1: Syscall Latency Microbenchmark (getpid × 1M iterations)"
    echo "─────────────────────────────────────────────────────────────"

    local bench_bin="$PROJECT_ROOT/victim_bench"
    if [[ ! -x "$bench_bin" ]]; then
        warn "victim_bench not found, skipping latency test"
        return
    fi

    local LOADER="$PROJECT_ROOT/loader"

    # Native
    local tmpout
    tmpout=$(mktemp)
    "$bench_bin" > "$tmpout" 2>/dev/null </dev/null || true
    local native_avg
    native_avg=$(grep -m1 'BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
    local native_iters
    native_iters=$(grep -m1 'BENCH_ITERATIONS=' "$tmpout" | cut -d= -f2)
    ok "Native:     ${BOLD}${native_avg:-?} ns/syscall${NC}  ($native_iters iterations)"

    # Enforced
    "$LOADER" "$bench_bin" > "$tmpout" 2>&1 </dev/null || true
    local enforced_avg
    enforced_avg=$(grep -m1 'BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
    ok "Enforced:   ${BOLD}${enforced_avg:-?} ns/syscall${NC}  ($native_iters iterations)"

    local overhead=0
    local pct="0"
    if [[ -n "$native_avg" && -n "$enforced_avg" && "$native_avg" -gt 0 ]]; then
        overhead=$((enforced_avg - native_avg))
        pct=$(awk "BEGIN { printf \"%.2f\", ($overhead / $native_avg) * 100 }")
    fi

    echo ""
    echo "  ${BOLD}Native latency:     ${native_avg:-?} ns${NC}"
    echo "  ${BOLD}Enforced latency:   ${enforced_avg:-?} ns${NC}"
    echo "  ${BOLD}eBPF overhead:      ${overhead} ns/syscall (${pct}%)${NC}"
    echo ""

    if [[ "$overhead" -lt 500 ]]; then
        ok "Overhead within wire-speed threshold (< 500 ns)"
    elif [[ "$overhead" -lt 1000 ]]; then
        warn "Overhead moderate (< 1µs) — acceptable for most workloads"
    else
        fail "Overhead exceeds 1µs — investigate system load"
    fi

    NATIVE_NS="$native_avg"
    ENFORCED_NS="$enforced_avg"
    OVERHEAD_NS="$overhead"
    OVERHEAD_PCT="$pct"

    rm -f "$tmpout"
}

# ══════════════════════════════════════════════════════
# Phase 2: I/O-Heavy Workload
# ══════════════════════════════════════════════════════
bench_io_heavy() {
    info "Phase 2: I/O-Heavy Workload (write 500K lines to /dev/null)"
    echo "─────────────────────────────────────────────────────────────"

    local io_src="/tmp/sentinel_io_bench.c"
    local io_bin="/tmp/sentinel_io_bench"

    cat > "$io_src" << 'IOSRC'
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    struct timespec start, end;
    const char msg[] = "benchmark payload line for I/O throughput test\n";
    int fd = 1; // stdout — caller redirects to /dev/null
    int iters = 500000;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iters; i++)
        write(fd, msg, sizeof(msg) - 1);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);
    long avg_ns = elapsed_ns / iters;

    fprintf(stderr, "IO_BENCH_TOTAL_NS=%ld\n", elapsed_ns);
    fprintf(stderr, "IO_BENCH_AVG_NS=%ld\n", avg_ns);
    fprintf(stderr, "IO_BENCH_ITERATIONS=%d\n", iters);
    return 0;
}
IOSRC

    local PASS_SO="$PROJECT_ROOT/src/compiler/build/SentinelPass.so"
    local SIGN_TOOL="$PROJECT_ROOT/sign_tool"
    local LOADER="$PROJECT_ROOT/loader"

    # Build with instrumentation
    clang -fpass-plugin="$PASS_SO" -O2 -o "$io_bin" "$io_src" 2>/dev/null
    "$SIGN_TOOL" "$io_bin" "$PROJECT_ROOT/priv.pem" 2>/dev/null

    # Native
    local tmpout
    tmpout=$(mktemp)
    "$io_bin" > /dev/null 2>"$tmpout"
    local native_io
    native_io=$(grep -m1 'IO_BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
    ok "Native:     ${BOLD}${native_io:-?} ns/write${NC}"

    # Enforced
    "$LOADER" "$io_bin" > /dev/null 2>"$tmpout" || true
    local enforced_io
    enforced_io=$(grep -m1 'IO_BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
    ok "Enforced:   ${BOLD}${enforced_io:-?} ns/write${NC}"

    if [[ -n "$native_io" && -n "$enforced_io" && "$native_io" -gt 0 ]]; then
        local io_overhead=$((enforced_io - native_io))
        local io_pct
        io_pct=$(awk "BEGIN { printf \"%.2f\", ($io_overhead / $native_io) * 100 }")
        echo "  ${BOLD}I/O overhead:       ${io_overhead} ns/write (${io_pct}%)${NC}"
        IO_OVERHEAD_NS="$io_overhead"
        IO_OVERHEAD_PCT="$io_pct"
    fi

    rm -f "$tmpout" "$io_src" "$io_bin"
    echo ""
}

# ══════════════════════════════════════════════════════
# Phase 3: File-Open Storm
# ══════════════════════════════════════════════════════
bench_file_open() {
    info "Phase 3: File-Open Storm (openat+close × 100K)"
    echo "─────────────────────────────────────────────────────────────"

    local fo_src="/tmp/sentinel_fo_bench.c"
    local fo_bin="/tmp/sentinel_fo_bench"

    cat > "$fo_src" << 'FOSRC'
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    struct timespec start, end;
    int iters = 100000;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iters; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) close(fd);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L +
                      (end.tv_nsec - start.tv_nsec);
    long avg_ns = elapsed_ns / iters;

    fprintf(stderr, "FO_BENCH_TOTAL_NS=%ld\n", elapsed_ns);
    fprintf(stderr, "FO_BENCH_AVG_NS=%ld\n", avg_ns);
    fprintf(stderr, "FO_BENCH_ITERATIONS=%d\n", iters);
    return 0;
}
FOSRC

    local PASS_SO="$PROJECT_ROOT/src/compiler/build/SentinelPass.so"
    local SIGN_TOOL="$PROJECT_ROOT/sign_tool"
    local LOADER="$PROJECT_ROOT/loader"

    clang -fpass-plugin="$PASS_SO" -O2 -o "$fo_bin" "$fo_src" 2>/dev/null
    "$SIGN_TOOL" "$fo_bin" "$PROJECT_ROOT/priv.pem" 2>/dev/null

    local tmpout
    tmpout=$(mktemp)
    "$fo_bin" 2>"$tmpout"
    local native_fo
    native_fo=$(grep -m1 'FO_BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
    ok "Native:     ${BOLD}${native_fo:-?} ns/open+close${NC}"

    "$LOADER" "$fo_bin" 2>"$tmpout" || true
    local enforced_fo
    enforced_fo=$(grep -m1 'FO_BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
    ok "Enforced:   ${BOLD}${enforced_fo:-?} ns/open+close${NC}"

    if [[ -n "$native_fo" && -n "$enforced_fo" && "$native_fo" -gt 0 ]]; then
        local fo_overhead=$((enforced_fo - native_fo))
        local fo_pct
        fo_pct=$(awk "BEGIN { printf \"%.2f\", ($fo_overhead / $native_fo) * 100 }")
        echo "  ${BOLD}File-open overhead: ${fo_overhead} ns/open+close (${fo_pct}%)${NC}"
        FO_OVERHEAD_NS="$fo_overhead"
        FO_OVERHEAD_PCT="$fo_pct"
    fi

    rm -f "$tmpout" "$fo_src" "$fo_bin"
    echo ""
}

# ══════════════════════════════════════════════════════
# Phase 4: Attack Surface Reduction
# ══════════════════════════════════════════════════════
bench_attack_surface() {
    info "Phase 4: Attack Surface Reduction (per-app libc filtering)"
    echo "─────────────────────────────────────────────────────────────"

    local LOADER="$PROJECT_ROOT/loader"
    local phase2_bin="$PROJECT_ROOT/victim_phase2"

    if [[ ! -x "$phase2_bin" ]]; then
        warn "victim_phase2 not found, skipping attack surface test"
        return
    fi

    local tmpout
    tmpout=$(mktemp)
    "$LOADER" --audit "$phase2_bin" > "$tmpout" 2>&1 </dev/null &
    local lpid=$!
    sleep 2
    kill "$lpid" 2>/dev/null || true
    wait "$lpid" 2>/dev/null || true

    local reduction
    reduction=$(grep -o '[0-9.]*% reduction' "$tmpout" | head -1)
    local sites_info
    sites_info=$(grep -o '[0-9]*/[0-9]* libc sites' "$tmpout" | head -1)
    local imports
    imports=$(grep -o '[0-9]* imports' "$tmpout" | head -1)
    local reachable
    reachable=$(grep -o '[0-9]* reachable functions' "$tmpout" | head -1)

    if [[ -n "$reduction" ]]; then
        ok "Per-app syscall reduction: ${BOLD}${reduction}${NC}"
        [[ -n "$sites_info" ]] && echo "  Sites whitelisted: $sites_info"
        [[ -n "$imports" ]] && echo "  Binary imports:    $imports"
        [[ -n "$reachable" ]] && echo "  Reachable funcs:   $reachable"
    else
        warn "Could not extract reduction data"
    fi

    rm -f "$tmpout"
    echo ""
}

# ══════════════════════════════════════════════════════
# Phase 5: Real-World Binary Test (HTTP Server)
# ══════════════════════════════════════════════════════
bench_real_world() {
    info "Phase 5: Real-World HTTP Server Under Enforcement"
    echo "─────────────────────────────────────────────────────────────"

    local PASS_SO="$PROJECT_ROOT/src/compiler/build/SentinelPass.so"
    local SIGN_TOOL="$PROJECT_ROOT/sign_tool"
    local LOADER="$PROJECT_ROOT/loader"
    local httpd_src="$PROJECT_ROOT/tests/real_httpd.c"
    local httpd_bin="/tmp/sentinel_real_httpd"

    if [[ ! -f "$httpd_src" ]]; then
        warn "tests/real_httpd.c not found, skipping"
        return
    fi

    # Build with instrumentation
    info "Building real_httpd with Sentinel instrumentation..."
    clang -fpass-plugin="$PASS_SO" -O2 -o "$httpd_bin" "$httpd_src" 2>/dev/null
    "$SIGN_TOOL" "$httpd_bin" "$PROJECT_ROOT/priv.pem" 2>/dev/null
    ok "Built and signed real_httpd"

    # Show policy
    local dump="$PROJECT_ROOT/sentinel-dump"
    if [[ -x "$dump" ]]; then
        local sites
        sites=$("$dump" "$httpd_bin" 2>/dev/null | grep -c '^\s*\[' || echo "?")
        ok "Policy: ${BOLD}${sites} syscall sites${NC} instrumented"
    fi

    # --- Native run ---
    info "Native HTTP server (no enforcement)..."
    "$httpd_bin" 9901 &
    local native_pid=$!
    sleep 0.5

    local tmpout
    tmpout=$(mktemp)
    # Blast 200 requests
    for i in $(seq 1 200); do
        curl -s -o /dev/null -w "%{time_total}\n" http://127.0.0.1:9901/ 2>/dev/null
    done > "$tmpout"
    kill "$native_pid" 2>/dev/null; wait "$native_pid" 2>/dev/null || true

    local native_avg_ms
    native_avg_ms=$(awk '{ total += $1; n++ } END { if(n>0) printf "%.2f", (total/n)*1000 }' "$tmpout")
    ok "Native:     ${BOLD}${native_avg_ms:-?} ms/request${NC} (200 requests)"

    # --- Enforced run ---
    info "Enforced HTTP server (under Sentinel-CC)..."
    "$LOADER" "$httpd_bin" 9902 > /dev/null 2>&1 &
    local enforced_loader_pid=$!
    sleep 1.5  # give loader time to verify + attach

    for i in $(seq 1 200); do
        curl -s -o /dev/null -w "%{time_total}\n" http://127.0.0.1:9902/ 2>/dev/null
    done > "$tmpout"
    kill "$enforced_loader_pid" 2>/dev/null; wait "$enforced_loader_pid" 2>/dev/null || true

    local enforced_avg_ms
    enforced_avg_ms=$(awk '{ total += $1; n++ } END { if(n>0) printf "%.2f", (total/n)*1000 }' "$tmpout")
    ok "Enforced:   ${BOLD}${enforced_avg_ms:-?} ms/request${NC} (200 requests)"

    if [[ -n "$native_avg_ms" && -n "$enforced_avg_ms" ]]; then
        local http_overhead
        http_overhead=$(awk "BEGIN { printf \"%.2f\", $enforced_avg_ms - $native_avg_ms }")
        local http_pct
        http_pct=$(awk "BEGIN { if($native_avg_ms > 0) printf \"%.1f\", (($enforced_avg_ms - $native_avg_ms) / $native_avg_ms) * 100; else print \"0\" }")
        echo "  ${BOLD}HTTP overhead:      ${http_overhead} ms/request (${http_pct}%)${NC}"
    fi

    rm -f "$tmpout" "$httpd_bin"
    echo ""
}

# ══════════════════════════════════════════════════════
# Phase 6: Policy Map Scalability
# ══════════════════════════════════════════════════════
bench_scalability() {
    info "Phase 6: Policy Map Scalability"
    echo "─────────────────────────────────────────────────────────────"

    # Count map entries for different binaries
    local DUMP="$PROJECT_ROOT/sentinel-dump"
    if [[ ! -x "$DUMP" ]]; then
        warn "sentinel-dump not found, skipping"
        return
    fi

    for bin in victim victim_phase2 victim_cfi victim_threaded; do
        local binpath="$PROJECT_ROOT/$bin"
        [[ -x "$binpath" ]] || continue
        local sites
        sites=$("$DUMP" "$binpath" 2>/dev/null | grep -c '^\s*\[' || echo "0")
        local imports
        imports=$("$DUMP" "$binpath" 2>/dev/null | grep 'Total:.*import' | grep -o '[0-9]*' | head -1 || echo "0")
        local cfi
        cfi=$("$DUMP" "$binpath" 2>/dev/null | grep 'Total:.*CFI' | grep -o '[0-9]*' | head -1 || echo "0")
        echo "  ${BOLD}$bin${NC}: ${sites} syscall sites, ${imports:-0} imports, ${cfi:-0} CFI entries"
    done

    # BPF map limits
    echo ""
    echo "  Map capacity:"
    echo "    inner_policy:    4096 entries/module (configurable)"
    echo "    policy_registry: 64 modules max"
    echo "    vma_map:         512 entries (LPM trie)"
    echo "    cfi_policy:      1024 entries"
    echo "    audit_ringbuf:   256 KB"
    echo ""
}

# ══════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Summary${NC}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  ┌──────────────────────────────┬───────────┬───────────┬──────────┐"
    echo "  │ Workload                     │ Native    │ Enforced  │ Overhead │"
    echo "  ├──────────────────────────────┼───────────┼───────────┼──────────┤"
    printf "  │ %-28s │ %7s ns│ %7s ns│ %6s ns │\n" \
        "getpid (pure syscall)" "${NATIVE_NS:-?}" "${ENFORCED_NS:-?}" "${OVERHEAD_NS:-?}"
    printf "  │ %-28s │ %7s ns│ %7s ns│ %6s ns │\n" \
        "write (I/O heavy)" "${NATIVE_IO:-?}" "${ENFORCED_IO:-?}" "${IO_OVERHEAD_NS:-?}"
    printf "  │ %-28s │ %7s ns│ %7s ns│ %6s ns │\n" \
        "open+close (file storm)" "${NATIVE_FO:-?}" "${ENFORCED_FO:-?}" "${FO_OVERHEAD_NS:-?}"
    echo "  └──────────────────────────────┴───────────┴───────────┴──────────┘"
    echo ""
    echo "  Kernel:            $(uname -r)"
    echo "  BPF hot-path ops:  3 map lookups + 1 comparison"
    echo "  Audit (when on):   1 ringbuf_reserve + 1 ringbuf_submit"
    echo ""
}

# ══════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════

# Need root for BPF
if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root (eBPF requires CAP_SYS_ADMIN)"
    echo "Usage: sudo $0"
    exit 1
fi

# Ensure keyring
keyctl add user sentinel:pubkey "$(cat "$PROJECT_ROOT/pub.pem")" @s >/dev/null 2>&1 || true

# Initialize globals
NATIVE_NS="" ENFORCED_NS="" OVERHEAD_NS="" OVERHEAD_PCT=""
IO_OVERHEAD_NS="" IO_OVERHEAD_PCT=""
FO_OVERHEAD_NS="" FO_OVERHEAD_PCT=""
NATIVE_IO="" ENFORCED_IO=""
NATIVE_FO="" ENFORCED_FO=""

header
bench_latency
bench_io_heavy
bench_file_open
bench_attack_surface
bench_real_world
bench_scalability
print_summary

echo "Done."
