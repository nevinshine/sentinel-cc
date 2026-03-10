#!/usr/bin/env bash
# scc — Sentinel-CC Unified CLI
# A git-style command interface for the Sentinel-CC toolchain.
#
# Usage: scc <command> [options] [args...]

set -euo pipefail

VERSION="4.5.0"

# ── Colors ───────────────────────────────────────────────────────────
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

# ── Resolve tool locations ──────────────────────────────────────────
# Check adjacent directory first (dev mode), then PATH (installed mode)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Walk up from src/cli to project root
if [[ -f "$SCRIPT_DIR/../../Makefile" ]]; then
  PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
  PROJECT_ROOT="$PWD"
fi

find_tool() {
  local name="$1"
  local installed_name="${2:-$1}"
  if [[ -x "$PROJECT_ROOT/$name" ]]; then
    echo "$PROJECT_ROOT/$name"
  elif command -v "$installed_name" &>/dev/null; then
    command -v "$installed_name"
  else
    echo ""
  fi
}

LOADER="$(find_tool loader sentinel-loader)"
SIGN_TOOL="$(find_tool sign_tool sentinel-sign)"
DUMP_TOOL="$(find_tool sentinel-dump sentinel-dump)"
TUI_TOOL="$(find_tool sentinel-tui sentinel-tui)"

# ── Helpers ──────────────────────────────────────────────────────────
die()    { echo -e "${RED}error:${NC} $*" >&2; exit 1; }
warn()   { echo -e "${YELLOW}warn:${NC} $*" >&2; }
info()   { echo -e "${BLUE}::${NC} $*"; }
ok()     { echo -e "${GREEN}✓${NC} $*"; }
failmk() { echo -e "${RED}✗${NC} $*"; }

need_root() {
  if [[ $(id -u) -ne 0 ]]; then
    die "This command requires root. Run: ${BOLD}sudo scc $*${NC}"
  fi
}

need_tool() {
  local var="$1" name="$2"
  if [[ -z "$var" ]]; then
    die "$name not found. Run ${BOLD}make${NC} in the project directory first, or install with ${BOLD}make install${NC}."
  fi
}

# ── COMMAND: help ────────────────────────────────────────────────────
cmd_help() {
  cat <<EOF
${BOLD}scc${NC} — Sentinel-CC Unified CLI v${VERSION}

${BOLD}USAGE${NC}
  scc <command> [options] [args...]

${BOLD}COMMANDS${NC}
  ${GREEN}build${NC} <src.c> [-o out]       Compile + instrument + sign a binary
  ${GREEN}sign${NC} <binary>                Sign an already-instrumented binary
  ${GREEN}run${NC} [opts] <binary> [args]   Run a binary under Sentinel protection
  ${GREEN}ui${NC} [opts] <binary> [args]    Run with live TUI dashboard
  ${GREEN}bench${NC} [binary]               Run latency benchmark
  ${GREEN}test${NC}                         Run the full test suite
  ${GREEN}dump${NC} <binary>                Inspect embedded policy
  ${GREEN}features${NC}                     Show supported features
  ${GREEN}status${NC}                       Check system readiness
  ${GREEN}version${NC}                      Show version
  ${GREEN}help${NC}                         Show this help

${BOLD}EXAMPLES${NC}
  scc build tests/victim.c -o victim
  scc run ./victim
  scc run --permissive ./victim
  scc run --enforce=term --watch-dlopen ./victim
  scc run --cgroup=/sys/fs/cgroup/myapp ./victim
  scc ui --audit ./victim_phase2
  scc bench
  scc test
  scc dump ./victim
  scc features

${BOLD}LOADER OPTIONS${NC} (for run/ui commands)
  --audit                   Enable audit logging
  --permissive              Log violations but do not kill
  --enforce=kill|permissive|term  Set enforcement mode (default: kill)
  --watch-dlopen            Monitor for dlopen'd libraries at runtime
  --cgroup=PATH             Restrict enforcement to a cgroup
  --learn                   Learning mode: record syscall profile
  --shadow-cfi              Enable shadow stack CFI validation
  --system-wide             Enforce fallback for ALL processes
  --surface                 Print attack surface report and exit
  --tpm                     Use TPM2 Root of Trust for verification

${DIM}https://github.com/nevinshine/sentinel-cc${NC}
EOF
}

# ── COMMAND: version ─────────────────────────────────────────────────
cmd_version() {
  echo -e "${BOLD}Sentinel-CC${NC} v${VERSION}"
}

# ── COMMAND: build ───────────────────────────────────────────────────
cmd_build() {
  local src="" output="" extra_flags=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) shift; output="$1" ;;
      -*) extra_flags+=("$1") ;;
      *)  src="$1" ;;
    esac
    shift
  done

  [[ -n "$src" ]] || die "Usage: scc build <source.c> [-o output]"
  [[ -f "$src" ]] || die "Source file not found: $src"

  # Derive output name
  if [[ -z "$output" ]]; then
    output="$(basename "${src%.c}")"
  fi

  # Find the LLVM pass
  local pass_so=""
  for candidate in \
    "$PROJECT_ROOT/src/compiler/build/SentinelPass.so" \
    "/usr/local/lib/SentinelPass.so" \
    "/usr/lib/SentinelPass.so"; do
    if [[ -f "$candidate" ]]; then
      pass_so="$candidate"
      break
    fi
  done
  [[ -n "$pass_so" ]] || die "SentinelPass.so not found. Run ${BOLD}make${NC} in src/compiler/build/ first."

  need_tool "$SIGN_TOOL" "sign_tool"

  # Check for keys
  local priv_key=""
  for candidate in "$PROJECT_ROOT/priv.pem" "priv.pem"; do
    if [[ -f "$candidate" ]]; then
      priv_key="$candidate"
      break
    fi
  done
  [[ -n "$priv_key" ]] || die "priv.pem not found. Run ${BOLD}make keys${NC} first."

  info "Compiling with SentinelPass: ${BOLD}$src${NC} → ${BOLD}$output${NC}"
  clang -fpass-plugin="$pass_so" -O2 "${extra_flags[@]+"${extra_flags[@]}"}" "$src" -o "$output"
  ok "Compiled"

  info "Signing binary..."
  "$SIGN_TOOL" "$output" "$priv_key"
  ok "Signed: $output"

  echo ""
  echo -e "${GREEN}Ready.${NC} Run with: ${BOLD}scc run $output${NC}"
}

# ── COMMAND: sign ────────────────────────────────────────────────────
cmd_sign() {
  [[ $# -ge 1 ]] || die "Usage: scc sign <binary>"

  local binary="$1"
  [[ -f "$binary" ]] || die "Binary not found: $binary"
  need_tool "$SIGN_TOOL" "sign_tool"

  local priv_key=""
  for candidate in "$PROJECT_ROOT/priv.pem" "priv.pem"; do
    if [[ -f "$candidate" ]]; then
      priv_key="$candidate"
      break
    fi
  done
  [[ -n "$priv_key" ]] || die "priv.pem not found. Run ${BOLD}make keys${NC} first."

  info "Signing ${BOLD}$binary${NC}..."
  "$SIGN_TOOL" "$binary" "$priv_key"
  ok "Signed: $binary"
}

# ── COMMAND: run ─────────────────────────────────────────────────────
cmd_run() {
  [[ $# -ge 1 ]] || die "Usage: scc run [loader-opts] <binary> [args...]"
  need_tool "$LOADER" "loader"
  need_root "run" "$@"

  # Setup keyring silently
  setup_keyring_silent

  info "Running under Sentinel protection..."
  exec "$LOADER" "$@"
}

# ── COMMAND: ui ──────────────────────────────────────────────────────
cmd_ui() {
  [[ $# -ge 1 ]] || die "Usage: scc ui [loader-opts] <binary> [args...]"
  need_tool "$LOADER" "loader"
  need_tool "$TUI_TOOL" "sentinel-tui"
  need_root "ui" "$@"

  setup_keyring_silent

  info "Launching Sentinel TUI dashboard..."
  echo ""

  # Run loader with JSON audit, pipe to TUI
  # stderr from loader goes to /dev/null (status messages), stdout has JSON
  "$LOADER" --audit --audit-format=json "$@" 2>/dev/null | "$TUI_TOOL"
}

# ── COMMAND: dump ────────────────────────────────────────────────────
cmd_dump() {
  [[ $# -ge 1 ]] || die "Usage: scc dump <binary>"
  need_tool "$DUMP_TOOL" "sentinel-dump"

  "$DUMP_TOOL" "$@"
}

# ── COMMAND: bench ───────────────────────────────────────────────────
cmd_bench() {
  need_root "bench"

  local bench_bin="" iterations=5

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--iterations) shift; iterations="$1" ;;
      -*) die "Unknown option: $1" ;;
      *)  bench_bin="$1" ;;
    esac
    shift
  done

  # Default to the project's benchmark binary
  if [[ -z "$bench_bin" ]]; then
    for candidate in "$PROJECT_ROOT/victim_bench" "./victim_bench"; do
      if [[ -x "$candidate" ]]; then
        bench_bin="$candidate"
        break
      fi
    done
  fi

  [[ -n "$bench_bin" && -x "$bench_bin" ]] || die "Benchmark binary not found. Run ${BOLD}make victim_bench${NC} first."
  need_tool "$LOADER" "loader"

  setup_keyring_silent

  _SCC_TMPOUT=$(mktemp /tmp/scc_bench.XXXXXX)
  trap 'rm -f "$_SCC_TMPOUT"' EXIT
  local tmpout="$_SCC_TMPOUT"

  echo ""
  echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Sentinel-CC Latency Benchmark${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
  echo ""

  # ── Phase 1: Native ──
  info "Phase 1: Native execution (no enforcement)"
  "$bench_bin" > "$tmpout" 2>/dev/null </dev/null
  local native_avg native_total native_iters
  native_avg=$(grep -m1 'BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
  native_total=$(grep -m1 'BENCH_TOTAL_NS=' "$tmpout" | cut -d= -f2)
  native_iters=$(grep -m1 'BENCH_ITERATIONS=' "$tmpout" | cut -d= -f2)

  [[ -n "$native_avg" ]] || die "Failed to parse native benchmark output"
  ok "Native:   ${BOLD}${native_avg} ns/syscall${NC}  (${native_iters} iterations)"

  # ── Phase 2: Enforced ──
  info "Phase 2: Sentinel-enforced execution"
  "$LOADER" "$bench_bin" > "$tmpout" 2>&1 </dev/null || true
  local enforced_avg enforced_total
  enforced_avg=$(grep -m1 'BENCH_AVG_NS=' "$tmpout" | cut -d= -f2)
  enforced_total=$(grep -m1 'BENCH_TOTAL_NS=' "$tmpout" | cut -d= -f2)

  [[ -n "$enforced_avg" ]] || die "Failed to parse enforced benchmark output"
  ok "Enforced: ${BOLD}${enforced_avg} ns/syscall${NC}  (${native_iters} iterations)"

  # ── Results ──
  local overhead=$(( enforced_avg - native_avg ))
  local pct="N/A"
  if [[ "$native_avg" -gt 0 ]]; then
    local pct_x100=$(( (overhead * 10000) / native_avg ))
    local pct_int=$((pct_x100 / 100))
    local pct_frac=$((pct_x100 % 100))
    [[ $pct_frac -lt 0 ]] && pct_frac=$((-pct_frac))
    pct="${pct_int}.$(printf '%02d' $pct_frac)%"
  fi

  echo ""
  echo -e "${BOLD}── Results ──────────────────────────────────────────${NC}"
  echo -e "  Native latency:     ${GREEN}${native_avg} ns${NC}"
  echo -e "  Enforced latency:   ${YELLOW}${enforced_avg} ns${NC}"
  echo -e "  eBPF overhead:      ${BOLD}${overhead} ns/syscall${NC} ($pct)"
  echo -e "${BOLD}─────────────────────────────────────────────────────${NC}"

  if [[ "$overhead" -le 500 ]]; then
    ok "Overhead within wire-speed threshold (< 500 ns)"
  elif [[ "$overhead" -le 1000 ]]; then
    warn "Overhead is moderate (< 1µs). Acceptable for most workloads."
  else
    warn "Overhead exceeds 1µs. Check system load."
  fi

  # ── Phase 3: Attack surface ──
  local phase2_bin=""
  for candidate in "$PROJECT_ROOT/victim_phase2" "./victim_phase2"; do
    [[ -x "$candidate" ]] && phase2_bin="$candidate" && break
  done

  if [[ -n "$phase2_bin" ]]; then
    echo ""
    info "Phase 3: Attack surface reduction"
    "$LOADER" --audit "$phase2_bin" > "$tmpout" 2>&1 </dev/null || true

    local reduction
    reduction=$(grep -o '[0-9.]*% reduction' "$tmpout" | head -1)
    if [[ -n "$reduction" ]]; then
      ok "Per-app syscall reduction: ${BOLD}${reduction}${NC}"
    fi
  fi

  echo ""
}

# ── COMMAND: test ────────────────────────────────────────────────────
cmd_test() {
  need_root "test"

  local test_script=""
  for candidate in "$PROJECT_ROOT/tests/run_all.sh" "tests/run_all.sh"; do
    if [[ -f "$candidate" ]]; then
      test_script="$candidate"
      break
    fi
  done
  [[ -n "$test_script" ]] || die "Test suite not found — run from project root."

  setup_keyring_silent

  echo ""
  echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Sentinel-CC Test Suite${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
  echo ""

  exec bash "$test_script"
}

# ── COMMAND: features ────────────────────────────────────────────────
cmd_features() {
  echo ""
  echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Sentinel-CC v${VERSION} — Feature Matrix${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "${BOLD}  Compiler Pass (SentinelPass)${NC}"
  echo -e "    ${GREEN}✓${NC} Inline syscall detection (asm volatile)"
  echo -e "    ${GREEN}✓${NC} Static offset analysis"
  echo -e "    ${GREEN}✓${NC} Call-graph BFS for per-app libc filtering"
  echo -e "    ${GREEN}✓${NC} CFI symbol table generation (.sentinel_cfi)"
  echo -e "    ${GREEN}✓${NC} Obfuscated syscall detection (xor / mov / lea)"
  echo -e "    ${GREEN}✓${NC} Import table for shared library awareness"
  echo ""
  echo -e "${BOLD}  eBPF Kernel Enforcer${NC}"
  echo -e "    ${GREEN}✓${NC} 16 fentry hooks (write, read, openat, mmap, ...)"
  echo -e "    ${GREEN}✓${NC}  5 fexit hooks (post-syscall return auditing)"
  echo -e "    ${GREEN}✓${NC} Fork/clone tracking (sched_process_fork)"
  echo -e "    ${GREEN}✓${NC} Per-process BPF map isolation (TGID-keyed)"
  echo -e "    ${GREEN}✓${NC} Offset + CFI dual verification"
  echo -e "    ${GREEN}✓${NC} Generalized CFI (arbitrary call-depth)"
  echo ""
  echo -e "${BOLD}  Runtime Loader${NC}"
  echo -e "    ${GREEN}✓${NC} Ed25519 signature verification (kernel keyring)"
  echo -e "    ${GREEN}✓${NC} ASLR-aware shared library base resolution"
  echo -e "    ${GREEN}✓${NC} LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH sanitization"
  echo -e "    ${GREEN}✓${NC} SIGHUP policy hot-reload"
  echo -e "    ${GREEN}✓${NC} JSON + text audit output"
  echo -e "    ${GREEN}✓${NC} Syslog integration"
  echo -e "    ${GREEN}✓${NC} Key revocation list checking"
  echo -e "    ${GREEN}✓${NC} Tamper detection"
  echo ""
  echo -e "${BOLD}  Tooling${NC}"
  echo -e "    ${GREEN}✓${NC} sentinel-sign — Ed25519 binary signing"
  echo -e "    ${GREEN}✓${NC} sentinel-dump — policy inspector"
  echo -e "    ${GREEN}✓${NC} sentinel-tui  — live terminal dashboard"
  echo -e "    ${GREEN}✓${NC} scc           — unified CLI (this tool)"
  echo ""
  echo -e "${BOLD}  Security${NC}"
  echo -e "    ${GREEN}✓${NC} Red team suite (10 attack vectors)"
  echo -e "    ${GREEN}✓${NC} Tamper detection via Ed25519 signatures"
  echo -e "    ${GREEN}✓${NC} Key rotation + revocation"
  echo -e "    ${GREEN}✓${NC} LD_PRELOAD defense"
  echo -e "    ${GREEN}✓${NC} Data-only attack resistance (CFI)"
  echo ""
  echo -e "${BOLD}  Platform${NC}"
  echo -e "    ${GREEN}✓${NC} x86-64 native"
  echo -e "    ${GREEN}✓${NC} ARM64 cross-compilation (CI verified)"
  echo -e "    ${GREEN}✓${NC} GitHub Actions CI (3-tier)"
  echo -e "    ${GREEN}✓${NC} systemd service template"
  echo -e "    ${GREEN}✓${NC} Man pages for all tools"
  echo ""
}

# ── COMMAND: status ──────────────────────────────────────────────────
cmd_status() {
  echo ""
  echo -e "${BOLD}  Sentinel-CC System Status${NC}"
  echo -e "${BOLD}  ─────────────────────────${NC}"
  echo ""

  local all_ok=1

  # Kernel version
  local kver
  kver=$(uname -r)
  echo -ne "  Kernel:           "
  local kmajor kminor
  kmajor=$(echo "$kver" | cut -d. -f1)
  kminor=$(echo "$kver" | cut -d. -f2)
  if [[ "$kmajor" -ge 6 ]] || { [[ "$kmajor" -eq 5 ]] && [[ "$kminor" -ge 8 ]]; }; then
    echo -e "${GREEN}$kver${NC}"
  else
    echo -e "${RED}$kver${NC} (need >= 5.8 for BPF)"
    all_ok=0
  fi

  # BTF
  echo -ne "  BTF:              "
  if [[ -f /sys/kernel/btf/vmlinux ]]; then
    echo -e "${GREEN}available${NC}"
  else
    echo -e "${RED}missing${NC} (/sys/kernel/btf/vmlinux)"
    all_ok=0
  fi

  # BPF filesystem
  echo -ne "  BPF filesystem:   "
  if mount | grep -q "type bpf"; then
    echo -e "${GREEN}mounted${NC}"
  else
    echo -e "${YELLOW}not mounted${NC} (may auto-mount)"
  fi

  # clang
  echo -ne "  Clang:            "
  if command -v clang &>/dev/null; then
    local cver
    cver=$(clang --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+\.\d+' | head -1)
    echo -e "${GREEN}$cver${NC}"
  else
    echo -e "${RED}not found${NC}"
    all_ok=0
  fi

  # bpftool
  echo -ne "  bpftool:          "
  if command -v bpftool &>/dev/null; then
    echo -e "${GREEN}found${NC}"
  else
    echo -e "${RED}not found${NC}"
    all_ok=0
  fi

  # openssl
  echo -ne "  OpenSSL:          "
  if command -v openssl &>/dev/null; then
    local over
    over=$(openssl version 2>/dev/null | awk '{print $2}')
    echo -e "${GREEN}$over${NC}"
  else
    echo -e "${RED}not found${NC}"
    all_ok=0
  fi

  # keyctl
  echo -ne "  keyctl:           "
  if command -v keyctl &>/dev/null; then
    echo -e "${GREEN}found${NC}"
  else
    echo -e "${RED}not found${NC}"
    all_ok=0
  fi

  # Keys
  echo -ne "  Keys (priv/pub):  "
  local priv_exists=0 pub_exists=0
  [[ -f "$PROJECT_ROOT/priv.pem" || -f "priv.pem" ]] && priv_exists=1
  [[ -f "$PROJECT_ROOT/pub.pem" || -f "pub.pem" ]] && pub_exists=1
  if [[ $priv_exists -eq 1 && $pub_exists -eq 1 ]]; then
    echo -e "${GREEN}both present${NC}"
  elif [[ $pub_exists -eq 1 ]]; then
    echo -e "${YELLOW}pub only${NC} (run: make keys)"
  else
    echo -e "${RED}missing${NC} (run: make keys)"
  fi

  # Keyring
  echo -ne "  Kernel keyring:   "
  if keyctl search @s user sentinel:pubkey &>/dev/null 2>&1; then
    echo -e "${GREEN}key loaded${NC}"
  else
    echo -e "${YELLOW}no key${NC} (run: make install-keys)"
  fi

  # SentinelPass
  echo -ne "  SentinelPass.so:  "
  local pass_found=0
  for p in "$PROJECT_ROOT/src/compiler/build/SentinelPass.so" /usr/local/lib/SentinelPass.so; do
    if [[ -f "$p" ]]; then
      echo -e "${GREEN}found${NC}"
      pass_found=1
      break
    fi
  done
  [[ $pass_found -eq 0 ]] && echo -e "${YELLOW}not built${NC} (run: make)"

  # Binaries
  echo -ne "  loader:           "
  [[ -n "$LOADER" ]] && echo -e "${GREEN}found${NC}" || { echo -e "${RED}not found${NC}"; all_ok=0; }
  echo -ne "  sign_tool:        "
  [[ -n "$SIGN_TOOL" ]] && echo -e "${GREEN}found${NC}" || echo -e "${YELLOW}not found${NC}"
  echo -ne "  sentinel-dump:    "
  [[ -n "$DUMP_TOOL" ]] && echo -e "${GREEN}found${NC}" || echo -e "${YELLOW}not found${NC}"
  echo -ne "  sentinel-tui:     "
  [[ -n "$TUI_TOOL" ]] && echo -e "${GREEN}found${NC}" || echo -e "${YELLOW}not found${NC}"

  echo ""
  if [[ $all_ok -eq 1 ]]; then
    echo -e "  ${GREEN}${BOLD}System is ready.${NC}"
  else
    echo -e "  ${YELLOW}${BOLD}Some components missing — see above.${NC}"
  fi
  echo ""
}

# ── Keyring helper ───────────────────────────────────────────────────
setup_keyring_silent() {
  local pubkey=""
  for candidate in "$PROJECT_ROOT/pub.pem" "pub.pem"; do
    [[ -f "$candidate" ]] && pubkey="$candidate" && break
  done
  [[ -n "$pubkey" ]] || return 0

  keyctl add user sentinel:pubkey "$(cat "$pubkey")" @s > /dev/null 2>&1 || true
  local kid
  kid=$(keyctl search @s user sentinel:pubkey 2>/dev/null) || true
  if [[ -n "$kid" ]]; then
    keyctl setperm "$kid" 0x3f3f3f3f 2>/dev/null || true
  fi
}

# ── Main Dispatch ────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  cmd_help
  exit 0
fi

COMMAND="$1"
shift

case "$COMMAND" in
  build)    cmd_build "$@" ;;
  sign)     cmd_sign "$@" ;;
  run)      cmd_run "$@" ;;
  ui|tui)   cmd_ui "$@" ;;
  bench)    cmd_bench "$@" ;;
  test)     cmd_test "$@" ;;
  dump)     cmd_dump "$@" ;;
  features) cmd_features "$@" ;;
  status)   cmd_status "$@" ;;
  version|-v|--version) cmd_version ;;
  help|-h|--help) cmd_help ;;
  *)
    die "Unknown command: ${BOLD}$COMMAND${NC}\nRun ${BOLD}scc help${NC} for usage."
    ;;
esac
