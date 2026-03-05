#!/bin/bash
# Debug: clear trace, run loader, dump blocked events
set -e

# Clear trace
echo > /sys/kernel/debug/tracing/trace
echo 1 > /sys/kernel/debug/tracing/tracing_on

# Setup keyring
keyctl add user sentinel:pubkey "$(cat pub.pem)" @s > /dev/null 2>&1 || true

echo "=== Running loader with victim_bench ==="
./loader ./victim_bench 2>&1 || true

echo ""
echo "=== BPF Trace (BLOCK/MISMATCH events) ==="
grep -i "sentinel.*BLOCK\|sentinel.*MISMATCH\|sentinel.*FAIL" /sys/kernel/debug/tracing/trace | head -20

echo ""
echo "=== BPF Trace (ALL Sentinel events) ==="
grep -i "sentinel" /sys/kernel/debug/tracing/trace | head -30
