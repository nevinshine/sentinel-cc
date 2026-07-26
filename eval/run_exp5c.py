import subprocess
import time
import os
import sys
import numpy as np
import signal

def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True).decode()

def run_sqlite(mode, iterations=5):
    print(f"\n--- SQLite ({mode}) ---")
    results = []
    
    cmd = "./benchmarks/sqlite_bench /tmp/sentinel_bench.db"
    if mode == "sentinel":
        cmd = "./loader ./benchmarks/sqlite_bench /tmp/sentinel_bench.db"
        
    for i in range(iterations):
        if os.path.exists("/tmp/sentinel_bench.db"):
            os.remove("/tmp/sentinel_bench.db")
        print(f"  Run {i+1}/{iterations}...")
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
            for line in output.split('\n'):
                if "SQLITE_OPS_PER_SEC=" in line:
                    ops = float(line.split("=")[1].strip())
                    results.append(ops)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.output.decode()}")
            sys.exit(1)
            
    return {'mean': np.mean(results), 'std': np.std(results)}

def start_bpf_hooks():
    # Start loader in system-wide mode using victim_phase2 to keep it alive
    loader = subprocess.Popen(["./loader", "--system-wide", "./victim_phase2"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) # Give BPF hooks time to attach
    return loader

def stop_bpf_hooks(loader):
    if loader:
        loader.terminate()
        loader.wait()
        subprocess.run("pkill -9 -f './loader'", shell=True)
        subprocess.run("pkill -9 -f 'victim_phase2'", shell=True)

def run_redis(mode, iterations=5):
    print(f"\n--- Redis ({mode}) ---")
    results = []
    loader = None
    
    if mode == "sentinel":
        loader = start_bpf_hooks()
        
    server_cmd = "/usr/bin/redis-server --port 7777 --save \"\" --appendonly no --loglevel warning"
        
    for i in range(iterations):
        print(f"  Run {i+1}/{iterations}...")
        
        # Start server natively
        server = subprocess.Popen(server_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1) # wait for redis to start
        
        try:
            # Run benchmark
            bench_cmd = "redis-benchmark -p 7777 -n 100000 -c 50 -q -t set"
            output = subprocess.check_output(bench_cmd, shell=True).decode()
            for line in output.replace('\r', '\n').split('\n'):
                if "requests per second" in line:
                    tokens = line.split()
                    try:
                        idx = tokens.index("requests")
                        ops = float(tokens[idx - 1])
                        results.append(ops)
                    except (ValueError, IndexError):
                        pass
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
        finally:
            server.terminate()
            server.wait()
            subprocess.run("killall -9 redis-server 2>/dev/null", shell=True)
            time.sleep(0.5)
            
    if mode == "sentinel":
        stop_bpf_hooks(loader)
            
    return {'mean': np.mean(results), 'std': np.std(results)}

def run_curl(mode, iterations=5):
    print(f"\n--- Curl ({mode}) ---")
    results = []
    loader = None
    
    # Create a 10MB dummy file
    with open("/tmp/dummy10mb.bin", "wb") as f:
        f.write(os.urandom(10 * 1024 * 1024))
        
    if mode == "sentinel":
        loader = start_bpf_hooks()
        
    # Start HTTP server
    server = subprocess.Popen("python3 -m http.server 8000 --directory /tmp", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    cmd = "/usr/bin/curl -s -o /dev/null -w \"%{time_total}\" http://127.0.0.1:8000/dummy10mb.bin"
        
    for i in range(iterations):
        print(f"  Run {i+1}/{iterations}...")
        try:
            output = subprocess.check_output(cmd, shell=True).decode()
            time_sec = float(output.strip())
            # Convert to MB/s
            mbs = 10.0 / time_sec
            results.append(mbs)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            
    server.terminate()
    server.wait()
    os.remove("/tmp/dummy10mb.bin")
    
    if mode == "sentinel":
        stop_bpf_hooks(loader)
            
    return {'mean': np.mean(results), 'std': np.std(results)}


def main():
    print("--- Macrobenchmark Suite ---")
    
    native_sqlite = run_sqlite("native")
    sentinel_sqlite = run_sqlite("sentinel")
    
    native_redis = run_redis("native")
    sentinel_redis = run_redis("sentinel")
    
    native_curl = run_curl("native")
    sentinel_curl = run_curl("sentinel")
    
    print("\n\n--- Results Summary ---")
    print(f"{'Application':<15} | {'Native':<25} | {'Sentinel':<25} | {'Overhead (%)':<15}")
    print("-" * 85)
    
    def print_row(name, nat, sen, unit):
        n_mean = nat['mean']
        s_mean = sen['mean']
        try:
            overhead = (1.0 - (s_mean / n_mean)) * 100
            n_str = f"{n_mean:,.0f} ± {nat['std']:,.0f} {unit}"
            s_str = f"{s_mean:,.0f} ± {sen['std']:,.0f} {unit}"
            print(f"{name:<15} | {n_str:<25} | {s_str:<25} | {overhead:>5.2f}%")
        except ValueError:
            print(f"{name:<15} | {n_mean} ± {nat['std']} {unit} | {s_mean} ± {sen['std']} {unit} | {overhead}%")
        
    print_row("SQLite", native_sqlite, sentinel_sqlite, "ops/s")
    print_row("Redis", native_redis, sentinel_redis, "ops/s")
    print_row("Curl (10MB)", native_curl, sentinel_curl, "MB/s")

if __name__ == "__main__":
    main()
