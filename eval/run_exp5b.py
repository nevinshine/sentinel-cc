import subprocess
import re
import numpy as np
import sys

def run_bench(cmd, iterations=5):
    results = {}
    for i in range(iterations):
        print(f"  Run {i+1}/{iterations}...")
        try:
            output = subprocess.check_output(cmd, shell=True).decode()
        except subprocess.CalledProcessError as e:
            print(f"Error running {cmd}: {e}")
            sys.exit(1)
            
        # Parse output:
        # getpid:         0.2223s (44984255 ops/sec)
        for line in output.split('\n'):
            match = re.search(r"^(.*?):\s+([\d\.]+)s\s+\(([\d\.]+)\s+ops/sec\)", line.strip())
            if match:
                op = match.group(1).strip()
                latency = float(match.group(2))
                throughput = float(match.group(3))
                if op not in results:
                    results[op] = {'latency': [], 'throughput': []}
                results[op]['latency'].append(latency)
                results[op]['throughput'].append(throughput)
                
    # Aggregate
    agg = {}
    for op, data in results.items():
        agg[op] = {
            'latency_mean': np.mean(data['latency']),
            'latency_std': np.std(data['latency']),
            'throughput_mean': np.mean(data['throughput']),
            'throughput_std': np.std(data['throughput'])
        }
    return agg

def main():
    print("--- Dropping caches ---")
    subprocess.run("sync; echo 3 > /proc/sys/vm/drop_caches", shell=True)

    print("\n--- Running Native Baseline ---")
    native = run_bench("./tests/runtime_native", 5)
    
    print("\n--- Running Sentinel-Enabled ---")
    sentinel = run_bench("./loader ./tests/runtime_sentinel", 5)

    print("\n--- Results Summary (10M Iterations) ---")
    print(f"{'Operation':<20} | {'Native (ops/sec)':<25} | {'Sentinel (ops/sec)':<25} | {'Overhead (%)':<15}")
    print("-" * 90)
    for op in native.keys():
        n_tput = native[op]['throughput_mean']
        s_tput = sentinel[op]['throughput_mean']
        overhead = (1.0 - (s_tput / n_tput)) * 100
        
        n_str = f"{n_tput:,.0f} ± {native[op]['throughput_std']:,.0f}"
        s_str = f"{s_tput:,.0f} ± {sentinel[op]['throughput_std']:,.0f}"
        
        print(f"{op:<20} | {n_str:<25} | {s_str:<25} | {overhead:>5.2f}%")

if __name__ == "__main__":
    main()
