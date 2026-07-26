import os
import subprocess
import json
import re

opt_levels = ["O0", "O1", "O2", "O3", "Os"]
base_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(base_dir)
sqlite_dir = os.path.join(root_dir, "benchmarks", "sqlite", "sqlite-amalgamation-3430100")
pass_so = os.path.join(root_dir, "src", "compiler", "build", "SentinelPass.so")
dump_tool = os.path.join(root_dir, "sentinel-dump")

def get_section_size(binary):
    try:
        out = subprocess.check_output(f"objdump -h {binary}", shell=True, text=True)
        for line in out.splitlines():
            if ".llvm.syscall.bounds" in line:
                parts = line.split()
                # 25 .llvm.syscall.bounds 00000039  000000000000300c ...
                size_hex = parts[2]
                return int(size_hex, 16)
    except Exception as e:
        print(f"Error getting section size: {e}")
    return 0

results = []

for opt in opt_levels:
    print(f"Compiling with -{opt}...")
    binary_out = f"sqlite3_{opt}"
    cmd = f"clang -{opt} -fpass-plugin={pass_so} -pthread shell.c sqlite3.c -ldl -lm -o {binary_out}"
    try:
        subprocess.run(cmd, cwd=sqlite_dir, shell=True, check=True, capture_output=True)
        
        binary_path = os.path.join(sqlite_dir, binary_out)
        sec_size = get_section_size(binary_path)
        
        dump_cmd = f"{dump_tool} --json {binary_path}"
        dump_out = subprocess.check_output(dump_cmd, shell=True, text=True)
        
        data = json.loads(dump_out)
        entries = data.get("llvm_syscall_bounds", [])
        
        results.append({
            "opt": opt,
            "size": sec_size,
            "count": len(entries)
        })
    except subprocess.CalledProcessError as e:
        print(f"Failed to compile or dump -{opt}: {e}")
        if e.stderr: print(e.stderr.decode('utf-8'))

print("\n### Experiment 1: Optimization Stability (SQLite)\n")
print("| Opt Level | Metadata Size (bytes) | Syscall Sites Captured |")
print("|-----------|-----------------------|------------------------|")
for r in results:
    print(f"| -{r['opt']}       | {r['size']:<21} | {r['count']:<22} |")
