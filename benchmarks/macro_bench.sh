#!/bin/bash
# macro_bench.sh — Sentinel-CC Macro Benchmarks
# Measures throughput overhead for real-world workloads:
#   1. nginx (HTTP requests/sec via wrk)
#   2. Redis (ops/sec via redis-benchmark)
#   3. SQLite (inserts + reads via custom binary)
#
# Usage:  sudo ./benchmarks/macro_bench.sh [runs]
# Output: CSV summary + human-readable table

set -u

RUNS=${1:-30}
MAX_SECONDS=${2:-480}   # Internal watchdog: self-terminate after this many seconds (default 8 min)
CSV_OUT="benchmarks/results_macro.csv"
TMPOUT=$(mktemp /tmp/sentinel_macro.XXXXXX)

# Internal watchdog: kill ourselves if we exceed MAX_SECONDS
( sleep "$MAX_SECONDS"; echo "[WATCHDOG] $MAX_SECONDS seconds elapsed, self-terminating"; kill -TERM $$ 2>/dev/null ) &
WATCHDOG_PID=$!

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

die()   { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

# Track background pids for cleanup
PIDS=()
cleanup_servers() {
  for p in "${PIDS[@]:-}"; do
    [[ -z "$p" ]] && continue
    kill "$p" 2>/dev/null || true
    kill -9 "$p" 2>/dev/null || true
  done
  # Kill any leaked background processes so the CI runner can exit cleanly
  pkill -9 -f './loader' 2>/dev/null || true
  pkill -9 -f 'victim_phase2' 2>/dev/null || true
  killall -9 nginx 2>/dev/null || true
  killall -9 redis-server 2>/dev/null || true
}

trap 'kill "$WATCHDOG_PID" 2>/dev/null; rm -f "$TMPOUT"; cleanup_servers' EXIT
trap 'echo "[SIGTERM] cleaning up..."; cleanup_servers; exit 143' TERM INT

setup_keyring() {
  if [ ! -f pub.pem ]; then
    die "pub.pem not found. Run 'make' first."
  fi
  keyctl add user sentinel:pubkey "$(cat pub.pem)" @s > /dev/null 2>&1 || true
  local kid
  kid=$(keyctl search @s user sentinel:pubkey 2>/dev/null) || true
  if [ -n "$kid" ]; then
    keyctl setperm "$kid" 0x3f3f3f3f 2>/dev/null || true
  fi
}

# Compute mean and stddev from a file of numbers (one per line)
stats() {
  awk '{s+=$1; ss+=$1*$1; n++} END {
    m=s/n;
    v=(ss/n)-(m*m);
    sd=sqrt(v<0?0:v);
    printf "%.2f %.2f\n", m, sd
  }' "$1"
}

# ── Preconditions ──
[[ $(id -u) -eq 0 ]] || die "Must run as root"
[[ -x ./loader ]]     || die "loader not found. Run: make"

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Sentinel-CC Macro Benchmarks  (${RUNS} runs each)${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

mkdir -p benchmarks
echo "workload,mode,mean_throughput,stddev,unit" > "$CSV_OUT"
setup_keyring

# ═════════════════════════════════════════════════════════════════════
# 1. NGINX BENCHMARK
# ═════════════════════════════════════════════════════════════════════

# For system binaries (nginx, redis) we can't instrument them with the
# Sentinel compiler pass. Instead we measure the overhead of having
# Sentinel's 19 fentry BPF hooks globally attached while the workload runs.
# This captures the real-world cost: every hooked syscall traverses the
# fentry trampoline and hits the target_pid_map early-exit path.

# Start BPF hooks in system-wide mode using a long-running instrumented binary
start_bpf_hooks() {
  info "  Starting BPF hooks (loader --system-wide)..."
  ./loader --system-wide ./victim_phase2 > /dev/null 2>&1 &
  BPF_LOADER_PID=$!
  sleep 2  # Let BPF programs attach
  # Verify loader is running
  if ! kill -0 "$BPF_LOADER_PID" 2>/dev/null; then
    warn "  BPF loader (PID $BPF_LOADER_PID) exited early"
    BPF_LOADER_PID=""
    return 1
  fi
  info "  BPF hooks active (loader PID $BPF_LOADER_PID)"
}

stop_bpf_hooks() {
  if [[ -n "${BPF_LOADER_PID:-}" ]]; then
    kill "$BPF_LOADER_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$BPF_LOADER_PID" 2>/dev/null || true
    wait "$BPF_LOADER_PID" 2>/dev/null || true
    BPF_LOADER_PID=""
  fi
  # Belt-and-suspenders: kill any leftover loader/victim processes
  pkill -9 -f './loader' 2>/dev/null || true
  pkill -9 -f 'victim_phase2' 2>/dev/null || true
}

run_nginx_bench() {
  local mode=$1 # "native" or "bpf-active"
  local results_file
  results_file=$(mktemp /tmp/nginx_results.XXXXXX)

  # In "sentinel" mode, load BPF hooks system-wide before the benchmark loop
  if [[ "$mode" == "sentinel" ]]; then
    start_bpf_hooks
  fi

  for i in $(seq 1 "$RUNS"); do
    info "  nginx $mode run $i/$RUNS" >&2
    # Ensure port is free
    killall nginx 2>/dev/null || true; sleep 0.1
    nginx -c "$(pwd)/benchmarks/nginx_bench.conf" &
    local srv_pid=$!
    PIDS+=("$srv_pid")
    # Wait for nginx to actually listen
    for _w in $(seq 1 10); do
      if bash -c "echo >/dev/tcp/127.0.0.1/8765" 2>/dev/null; then break; fi
      sleep 0.2
    done

    # wrk: 1 thread, 8 connections, 2 seconds (laptop-safe)
    local rps
    rps=$(timeout 10 wrk -t1 -c8 -d2s http://127.0.0.1:8765/ 2>/dev/null | \
          grep 'Requests/sec' | awk '{print $2}')
    echo "${rps:-0}" >> "$results_file"

    # Stop nginx
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
    PIDS=("${PIDS[@]/$srv_pid/}")
    sleep 0.2
  done

  if [[ "$mode" == "sentinel" ]]; then
    stop_bpf_hooks
  fi

  local ms
  ms=$(stats "$results_file")
  local mean stddev
  mean=$(echo "$ms" | awk '{print $1}')
  stddev=$(echo "$ms" | awk '{print $2}')
  echo "nginx,$mode,$mean,$stddev,req/s" >> "$CSV_OUT"
  echo "$mean $stddev"
  rm -f "$results_file"
}

if command -v nginx &>/dev/null && command -v wrk &>/dev/null; then
  info "Benchmark 1: nginx (HTTP throughput)"

  # Stop system nginx to free ports/PIDs
  systemctl stop nginx 2>/dev/null || true
  killall nginx 2>/dev/null || true

  # Generate minimal nginx config if not present
  if [[ ! -f benchmarks/nginx_bench.conf ]]; then
    cat > benchmarks/nginx_bench.conf <<'NGINX_CONF'
daemon off;
worker_processes 1;
pid /tmp/sentinel_nginx.pid;
error_log /tmp/sentinel_nginx_err.log;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path /tmp/nginx_body;
  proxy_temp_path /tmp/nginx_proxy;
  fastcgi_temp_path /tmp/nginx_fastcgi;
  uwsgi_temp_path /tmp/nginx_uwsgi;
  scgi_temp_path /tmp/nginx_scgi;
  server {
    listen 8765;
    location / { return 200 "ok\n"; }
  }
}
NGINX_CONF
  fi

  native_nginx=$(run_nginx_bench native)
  sentinel_nginx=$(run_nginx_bench sentinel)
  native_mean=$(echo "$native_nginx" | awk '{print $1}')
  sentinel_mean=$(echo "$sentinel_nginx" | awk '{print $1}')
  ok "nginx native:   ${BOLD}${native_mean} req/s${NC}"
  ok "nginx sentinel: ${BOLD}${sentinel_mean} req/s${NC}"
else
  warn "Skipping nginx benchmark (install nginx + wrk)"
fi

# ═════════════════════════════════════════════════════════════════════
# 2. REDIS BENCHMARK
# ═════════════════════════════════════════════════════════════════════

run_redis_bench() {
  local mode=$1
  local results_file
  results_file=$(mktemp /tmp/redis_results.XXXXXX)

  if [[ "$mode" == "sentinel" ]]; then
    start_bpf_hooks
  fi

  for i in $(seq 1 "$RUNS"); do
    info "  redis $mode run $i/$RUNS" >&2
    # Ensure port is free
    killall redis-server 2>/dev/null || true; sleep 0.1
    redis-server --port 7777 --save "" --appendonly no --loglevel warning &
    local srv_pid=$!
    PIDS+=("$srv_pid")
    # Wait for redis to actually listen
    for _w in $(seq 1 10); do
      if bash -c "echo >/dev/tcp/127.0.0.1/7777" 2>/dev/null; then break; fi
      sleep 0.2
    done

    # 10k requests, 10 parallel, pipeline 8 (laptop-safe)
    local ops
    ops=$(timeout 15 redis-benchmark -p 7777 -n 10000 -c 10 -P 8 -q 2>/dev/null | \
          grep 'SET:' | awk '{print $2}')
    echo "${ops:-0}" >> "$results_file"

    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
    PIDS=("${PIDS[@]/$srv_pid/}")
    sleep 0.2
  done

  if [[ "$mode" == "sentinel" ]]; then
    stop_bpf_hooks
  fi

  local ms
  ms=$(stats "$results_file")
  local mean stddev
  mean=$(echo "$ms" | awk '{print $1}')
  stddev=$(echo "$ms" | awk '{print $2}')
  echo "redis,$mode,$mean,$stddev,ops/s" >> "$CSV_OUT"
  echo "$mean $stddev"
  rm -f "$results_file"
}

if command -v redis-server &>/dev/null && command -v redis-benchmark &>/dev/null; then
  info "Benchmark 2: Redis (SET throughput)"

  # Stop system redis to free port
  systemctl stop redis-server 2>/dev/null || true
  killall redis-server 2>/dev/null || true
  native_redis=$(run_redis_bench native)
  sentinel_redis=$(run_redis_bench sentinel)
  native_mean=$(echo "$native_redis" | awk '{print $1}')
  sentinel_mean=$(echo "$sentinel_redis" | awk '{print $1}')
  ok "Redis native:   ${BOLD}${native_mean} ops/s${NC}"
  ok "Redis sentinel: ${BOLD}${sentinel_mean} ops/s${NC}"
else
  warn "Skipping Redis benchmark (install redis-server + redis-benchmark)"
fi

# ═════════════════════════════════════════════════════════════════════
# 3. SQLITE BENCHMARK
# ═════════════════════════════════════════════════════════════════════

run_sqlite_bench() {
  local mode=$1
  local results_file
  results_file=$(mktemp /tmp/sqlite_results.XXXXXX)
  local db_path="/tmp/sentinel_bench.db"

  for i in $(seq 1 "$RUNS"); do
    info "  sqlite $mode run $i/$RUNS" >&2
    rm -f "$db_path"
    local elapsed

    if [[ "$mode" == "sentinel" ]]; then
      # sqlite_bench is Sentinel-instrumented, run directly under the loader
      local output
      output=$(timeout 30 ./loader ./benchmarks/sqlite_bench "$db_path" 2>&1) || true
      elapsed=$(echo "$output" | grep 'SQLITE_OPS_PER_SEC=' | cut -d= -f2)
      if [[ -z "$elapsed" || "$elapsed" == "0" ]] && [[ "$i" -eq 1 ]]; then
        warn "loader+sqlite_bench failed, sentinel sqlite benchmark unavailable" >&2
        echo "0" >> "$results_file"
        break
      fi
    else
      elapsed=$(./benchmarks/sqlite_bench "$db_path" 2>&1 | \
                grep 'SQLITE_OPS_PER_SEC=' | cut -d= -f2)
    fi
    echo "${elapsed:-0}" >> "$results_file"
  done

  local ms
  ms=$(stats "$results_file")
  local mean stddev
  mean=$(echo "$ms" | awk '{print $1}')
  stddev=$(echo "$ms" | awk '{print $2}')
  echo "sqlite,$mode,$mean,$stddev,ops/s" >> "$CSV_OUT"
  echo "$mean $stddev"
  rm -f "$results_file" "$db_path"
}

if [[ -x ./benchmarks/sqlite_bench ]]; then
  info "Benchmark 3: SQLite (insert+read throughput)"
  native_sqlite=$(run_sqlite_bench native)
  sentinel_sqlite=$(run_sqlite_bench sentinel)
  native_mean=$(echo "$native_sqlite" | awk '{print $1}')
  sentinel_mean=$(echo "$sentinel_sqlite" | awk '{print $1}')
  ok "SQLite native:   ${BOLD}${native_mean} ops/s${NC}"
  ok "SQLite sentinel: ${BOLD}${sentinel_mean} ops/s${NC}"
else
  warn "Skipping SQLite benchmark (build: cc -O2 benchmarks/sqlite_bench.c -lsqlite3 -o benchmarks/sqlite_bench)"
fi

# ═════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Results saved to ${CSV_OUT}${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
column -t -s, "$CSV_OUT" 2>/dev/null || cat "$CSV_OUT"
