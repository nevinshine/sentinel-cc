#!/bin/bash
# comparative.sh — Sentinel-CC Comparative Evaluation
# Runs the same workload under multiple security frameworks:
#   1. No protection (baseline)
#   2. Sentinel-CC (eBPF fentry enforcement)
#   3. seccomp-bpf (via libseccomp)
#   4. Landlock (filesystem restriction)
#   5. AppArmor (mandatory access control)
#
# Measures latency overhead per-syscall and outputs CSV.
# Usage: sudo ./eval/comparative.sh [iterations]

set -u

ITERS=${1:-100000}
RUNS=${2:-30}
CSV="eval/results_comparative.csv"

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

die()  { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }
info() { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

stats() {
  awk '{s+=$1; ss+=$1*$1; n++} END {
    m=s/n; v=(ss/n)-(m*m); sd=sqrt(v<0?0:v);
    printf "%.2f %.2f\n", m, sd
  }' "$1"
}

[[ $(id -u) -eq 0 ]] || die "Must run as root"
[[ -x ./victim_bench ]] || die "victim_bench not found. Run: make victim_bench"
[[ -x ./loader ]]     || die "loader not found. Run: make"

mkdir -p eval
echo "framework,mean_ns,stddev_ns,overhead_ns,overhead_pct" > "$CSV"

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Sentinel-CC Comparative Evaluation  (${RUNS} runs)${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""

# Helper: run victim_bench N times, collect avg ns
run_bench() {
  local label=$1
  shift
  local results_file
  results_file=$(mktemp /tmp/comp_bench.XXXXXX)

  info "Running: $label" >&2
  for i in $(seq 1 "$RUNS"); do
    local avg
    avg=$(timeout 30 "$@" 2>&1 | grep 'BENCH_AVG_NS=' | cut -d= -f2)
    echo "${avg:-0}" >> "$results_file"
  done

  local ms
  ms=$(stats "$results_file")
  rm -f "$results_file"
  echo "$ms"
}

setup_keyring() {
  keyctl add user sentinel:pubkey "$(cat pub.pem)" @s > /dev/null 2>&1 || true
  local kid
  kid=$(keyctl search @s user sentinel:pubkey 2>/dev/null) || true
  [ -n "$kid" ] && keyctl setperm "$kid" 0x3f3f3f3f 2>/dev/null || true
}

# ── 1. Baseline ──────────────────────────────────────────────────────
baseline=$(run_bench "baseline (no protection)" ./victim_bench)
baseline_mean=$(echo "$baseline" | awk '{print $1}')
baseline_sd=$(echo "$baseline" | awk '{print $2}')
echo "none,$baseline_mean,$baseline_sd,0,0.00" >> "$CSV"
ok "Baseline:     ${BOLD}${baseline_mean} ns/syscall${NC} (±${baseline_sd})"

# ── 2. Sentinel-CC ──────────────────────────────────────────────────
setup_keyring
sentinel=$(run_bench "Sentinel-CC (eBPF fentry)" ./loader ./victim_bench)
sentinel_mean=$(echo "$sentinel" | awk '{print $1}')
sentinel_sd=$(echo "$sentinel" | awk '{print $2}')
overhead=$(awk "BEGIN{printf \"%.2f\", $sentinel_mean - $baseline_mean}")
pct=$(awk "BEGIN{if($baseline_mean>0) printf \"%.2f\", ($overhead/$baseline_mean)*100; else print \"0\"}")
echo "sentinel-cc,$sentinel_mean,$sentinel_sd,$overhead,$pct" >> "$CSV"
ok "Sentinel-CC:  ${BOLD}${sentinel_mean} ns/syscall${NC} (±${sentinel_sd}) overhead: ${overhead} ns (${pct}%)"

# ── 3. seccomp-bpf ─────────────────────────────────────────────────
# Build seccomp harness if not present
if [[ ! -x eval/seccomp_harness ]] && command -v pkg-config &>/dev/null; then
  if pkg-config --exists libseccomp 2>/dev/null; then
    cat > eval/seccomp_harness.c <<'EOF'
/* Minimal seccomp-bpf harness: allow write, read, exit_group, clock_gettime */
#include <seccomp.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_load(ctx);
  seccomp_release(ctx);
  if (argc > 1) execvp(argv[1], argv + 1);
  return 0;
}
EOF
    cc -O2 eval/seccomp_harness.c -lseccomp -o eval/seccomp_harness 2>/dev/null || true
  fi
fi

if [[ -x eval/seccomp_harness ]]; then
  seccomp=$(run_bench "seccomp-bpf" eval/seccomp_harness ./victim_bench)
  seccomp_mean=$(echo "$seccomp" | awk '{print $1}')
  seccomp_sd=$(echo "$seccomp" | awk '{print $2}')
  overhead=$(awk "BEGIN{printf \"%.2f\", $seccomp_mean - $baseline_mean}")
  pct=$(awk "BEGIN{if($baseline_mean>0) printf \"%.2f\", ($overhead/$baseline_mean)*100; else print \"0\"}")
  echo "seccomp-bpf,$seccomp_mean,$seccomp_sd,$overhead,$pct" >> "$CSV"
  ok "seccomp-bpf:  ${BOLD}${seccomp_mean} ns/syscall${NC} (±${seccomp_sd}) overhead: ${overhead} ns (${pct}%)"
else
  warn "Skipping seccomp-bpf (install libseccomp-devel)"
fi

# ── 4. Landlock ─────────────────────────────────────────────────────
# Landlock restricts filesystem access. The syscall path includes
# an LSM hook check, so even a permissive Landlock adds measurable overhead.
if [[ ! -x eval/landlock_harness ]]; then
  cat > eval/landlock_harness.c <<'EOF'
/* Landlock harness: restrict filesystem to /tmp read-only */
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
int main(int argc, char **argv) {
  struct landlock_ruleset_attr rattr = {
    .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                         LANDLOCK_ACCESS_FS_READ_DIR |
                         LANDLOCK_ACCESS_FS_EXECUTE
  };
  int fd = syscall(SYS_landlock_create_ruleset, &rattr, sizeof(rattr), 0);
  if (fd >= 0) {
    struct landlock_path_beneath_attr pb = {
      .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE,
      .parent_fd = open("/", O_PATH | O_CLOEXEC)
    };
    if (pb.parent_fd >= 0) {
      syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
      close(pb.parent_fd);
    }
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_landlock_restrict_self, fd, 0);
    close(fd);
  }
  if (argc > 1) execvp(argv[1], argv + 1);
  return 0;
}
EOF
  cc -O2 eval/landlock_harness.c -o eval/landlock_harness 2>/dev/null || true
fi

if [[ -x eval/landlock_harness ]]; then
  landlock=$(run_bench "Landlock LSM" eval/landlock_harness ./victim_bench)
  landlock_mean=$(echo "$landlock" | awk '{print $1}')
  landlock_sd=$(echo "$landlock" | awk '{print $2}')
  overhead=$(awk "BEGIN{printf \"%.2f\", $landlock_mean - $baseline_mean}")
  pct=$(awk "BEGIN{if($baseline_mean>0) printf \"%.2f\", ($overhead/$baseline_mean)*100; else print \"0\"}")
  echo "landlock,$landlock_mean,$landlock_sd,$overhead,$pct" >> "$CSV"
  ok "Landlock:     ${BOLD}${landlock_mean} ns/syscall${NC} (±${landlock_sd}) overhead: ${overhead} ns (${pct}%)"
else
  warn "Skipping Landlock (kernel too old or build failed)"
fi

# ── 5. AppArmor ─────────────────────────────────────────────────────
if command -v aa-exec &>/dev/null && [[ -d /sys/kernel/security/apparmor ]]; then
  # Use unconfined profile as baseline (measures LSM hook overhead)
  apparmor=$(run_bench "AppArmor (unconfined)" aa-exec -p unconfined -- ./victim_bench)
  apparmor_mean=$(echo "$apparmor" | awk '{print $1}')
  apparmor_sd=$(echo "$apparmor" | awk '{print $2}')
  overhead=$(awk "BEGIN{printf \"%.2f\", $apparmor_mean - $baseline_mean}")
  pct=$(awk "BEGIN{if($baseline_mean>0) printf \"%.2f\", ($overhead/$baseline_mean)*100; else print \"0\"}")
  echo "apparmor,$apparmor_mean,$apparmor_sd,$overhead,$pct" >> "$CSV"
  ok "AppArmor:     ${BOLD}${apparmor_mean} ns/syscall${NC} (±${apparmor_sd}) overhead: ${overhead} ns (${pct}%)"
else
  warn "Skipping AppArmor (not available on this system)"
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Comparative Results  →  ${CSV}${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
column -t -s, "$CSV" 2>/dev/null || cat "$CSV"

echo ""
echo -e "${BOLD}Security Coverage Comparison:${NC}"
echo "┌───────────────┬──────────┬─────────┬──────────┬────────┬─────────┐"
echo "│ Feature       │ Sentinel │ seccomp │ Landlock │ AppAr. │ SELinux │"
echo "├───────────────┼──────────┼─────────┼──────────┼────────┼─────────┤"
echo "│ Per-app policy│    ✓     │    ✓    │    ✓     │   ✓    │    ✓    │"
echo "│ Call-site CFI │    ✓     │    ✗    │    ✗     │   ✗    │    ✗    │"
echo "│ Shadow stack  │    ✓     │    ✗    │    ✗     │   ✗    │    ✗    │"
echo "│ Binary signing│    ✓     │    ✗    │    ✗     │   ✗    │    ✗    │"
echo "│ Fork tracking │    ✓     │    ✓    │    ✓     │   ✓    │    ✓    │"
echo "│ Dep filtering │    ✓     │    ✗    │    ✗     │   ✗    │    ✗    │"
echo "│ Learn mode    │    ✓     │    ✗    │    ✗     │   ~    │    ~    │"
echo "│ BPF tamper    │    ✓     │    ✗    │    ✗     │   ✗    │    ~    │"
echo "│ No root req.  │    ✗     │    ✓    │    ✓     │   ✗    │    ✗    │"
echo "│ Kernel LSM    │    ✗     │    ✗    │    ✓     │   ✓    │    ✓    │"
echo "└───────────────┴──────────┴─────────┴──────────┴────────┴─────────┘"
