#!/bin/bash
# Quick debug: clear trace, run loader, show blocking events
echo > /sys/kernel/debug/tracing/trace
echo "[*] Running loader with victim_bench..."
# Setup keyring
keyctl add user sentinel:pubkey "$(cat pub.pem)" @s > /dev/null 2>&1 || true
./loader ./victim_bench 2>&1 &
LOADER_PID=$!
sleep 3
kill $LOADER_PID 2>/dev/null
wait $LOADER_PID 2>/dev/null
echo "[*] BPF trace events:"
cat /sys/kernel/debug/tracing/trace | grep -i "sentinel" | head -40
