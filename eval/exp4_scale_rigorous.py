#!/usr/bin/env python3
import os
import subprocess
import time
import json
import numpy as np
import matplotlib.pyplot as plt

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PASS_SO = os.path.join(ROOT_DIR, "src/compiler/build/SentinelPass.so")
DUMP_TOOL = os.path.join(ROOT_DIR, "sentinel-dump")

# Define applications and their build commands
APPS = {
    "BusyBox": {
        "dir": "benchmarks/busybox-1.36.1",
        "clean": "make clean",
        "build": f"make CC='clang -fpass-plugin={PASS_SO}' -j4",
        "binary": "busybox_unstripped"
    },
    "curl": {
        "dir": "benchmarks/curl-8.4.0",
        "clean": "make clean && ./configure --disable-shared --enable-static --without-ssl > /dev/null 2>&1",
        "build": f"make CC='clang -fpass-plugin={PASS_SO}' -j4",
        "binary": "src/curl"
    },
    "Redis": {
        "dir": "benchmarks/redis-7.2.3",
        "clean": "make clean",
        "build": f"make CC='clang' CFLAGS='-O2 -fpass-plugin={PASS_SO}' -j4",
        "binary": "src/redis-server"
    }
}

RUNS = 5
results = {}

def get_metadata(binary_path):
    # Get metadata size
    size_cmd = f"objdump -h {binary_path} | awk '/\\.llvm\\.syscall\\.bounds/{{print $3}}'"
    try:
        hex_size = subprocess.check_output(size_cmd, shell=True).decode().strip()
        size_bytes = int(hex_size, 16) if hex_size else 0
    except:
        size_bytes = 0
    
    # Get total syscall sites
    count_cmd = f"{DUMP_TOOL} --json {binary_path} | grep '\"site\"' | wc -l"
    try:
        count = int(subprocess.check_output(count_cmd, shell=True).decode().strip())
    except:
        count = 0
        
    return size_bytes, count

print("Starting rigorous static evaluation benchmark loop...")

for app, config in APPS.items():
    print(f"\n--- Benchmarking {app} ---")
    times = []
    
    for i in range(RUNS):
        print(f"  Run {i+1}/{RUNS}...")
        # Clean
        subprocess.run(config["clean"], cwd=config["dir"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Build and measure time
        start = time.time()
        res = subprocess.run(config["build"], cwd=config["dir"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time()
        
        if res.returncode == 0:
            times.append(end - start)
        else:
            print(f"    Build failed for {app} on run {i+1}")
            
    # Measure sizes once (it is deterministic)
    meta_size, sites = get_metadata(os.path.join(config["dir"], config["binary"]))
    
    mean_time = np.mean(times) if times else 0
    std_time = np.std(times) if times else 0
    
    results[app] = {
        "times": times,
        "mean_time": mean_time,
        "std_time": std_time,
        "meta_size": meta_size,
        "sites": sites
    }
    print(f"  Results for {app}: {mean_time:.2f}s +/- {std_time:.2f}s")

# Save JSON
with open("eval/scale_results.json", "w") as f:
    json.dump(results, f, indent=4)

# 1. Plot Syscall Sites vs Metadata Size
plt.figure(figsize=(8, 5))
sites = [results[app]["sites"] for app in APPS]
sizes = [results[app]["meta_size"] for app in APPS]
apps = list(APPS.keys())

plt.scatter(sites, sizes, color='blue', s=100)
for i, app in enumerate(apps):
    plt.annotate(app, (sites[i], sizes[i]), xytext=(5, 5), textcoords='offset points')

plt.title("Metadata Size vs Syscall Sites")
plt.xlabel("Total Syscall Sites Tracked")
plt.ylabel("Metadata Size (bytes)")
plt.grid(True, linestyle='--', alpha=0.7)
plt.savefig("eval/metadata_linear_growth.png", dpi=300, bbox_inches='tight')
plt.close()

# 2. Plot Build Times with Error Bars
plt.figure(figsize=(8, 5))
means = [results[app]["mean_time"] for app in APPS]
stds = [results[app]["std_time"] for app in APPS]

x_pos = np.arange(len(apps))
plt.bar(x_pos, means, yerr=stds, align='center', alpha=0.7, ecolor='black', capsize=10, color='coral')
plt.xticks(x_pos, apps)
plt.ylabel("Build Time (seconds)")
plt.title("Compilation Overhead (Mean over 5 Runs)")
plt.grid(True, axis='y', linestyle='--', alpha=0.7)
plt.savefig("eval/compilation_overhead_bars.png", dpi=300, bbox_inches='tight')
plt.close()

print("\nEvaluation complete. Graphs saved to eval/metadata_linear_growth.png and eval/compilation_overhead_bars.png")
