import os
import subprocess
import json
import re

base_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(base_dir)
binary_path = os.path.join(root_dir, "benchmarks", "sqlite", "sqlite-amalgamation-3430100", "sqlite3_O2")
dump_tool = os.path.join(root_dir, "sentinel-dump")

tracked_syscalls = {
    "write", "__write", "__libc_write", "read", "__read", "__libc_read", 
    "open", "__open", "__libc_open", "close", "__close", "__libc_close", "lseek", "openat", 
    "fstat", "stat", "lstat", "fstatat", "fork", "vfork", "clone", "execve", "execveat", 
    "mmap", "munmap", "mprotect", "mremap", "brk", "socket", "connect", "bind", "listen", 
    "accept", "accept4", "send", "sendto", "recv", "recvfrom", "sendmsg", "recvmsg", 
    "ptrace", "kill", "tkill", "tgkill", "sigaction", "rt_sigaction", "rt_sigprocmask",
    "printf", "fprintf", "vprintf", "vfprintf", "sprintf", "snprintf", "dprintf",
    "puts", "fputs", "putchar", "fputc", "putc",
    "fwrite", "fread", "fflush",
    "fopen", "fclose", "fdopen", "freopen", "fopen64", "fstat64", "lstat64", "stat64", "open64", "openat64",
    "fgets", "fgetc", "getchar", "getline", "getdelim",
    "perror", "syscall",
    "malloc", "free", "realloc", "calloc" # Sometimes these trigger brk/mmap, wait, are they tracked? No.
}

def get_objdump_syscalls(binary):
    cmd = f"objdump -d {binary}"
    syscall_addrs = []
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            if "call " in line or "call\t" in line:
                m = re.search(r'([0-9a-f]+):\s+[0-9a-f ]+\s+call\s+[0-9a-f*]+\s+<([^>]+)>', line)
                if m:
                    addr = int(m.group(1), 16)
                    target = m.group(2).split('@')[0].split('+')[0]
                    if target in tracked_syscalls:
                        syscall_addrs.append(addr)
    except Exception as e:
        print(f"Error running objdump: {e}")
    return syscall_addrs

def get_metadata_syscalls(binary):
    cmd = f"{dump_tool} --json {binary}"
    syscall_addrs = []
    try:
        out = subprocess.check_output(cmd, shell=True, text=True)
        data = json.loads(out)
        for entry in data.get("llvm_syscall_bounds", []):
            addr_str = entry.get("site")
            if addr_str:
                addr = int(addr_str, 16)
                if addr != 0:
                    syscall_addrs.append(addr)
    except Exception as e:
        print(f"Error parsing metadata: {e}")
    return syscall_addrs

if not os.path.exists(binary_path):
    print(f"Binary not found: {binary_path}. Run exp1_opt_stability.py first.")
    exit(1)

ground_truth = sorted(get_objdump_syscalls(binary_path))
metadata = sorted(get_metadata_syscalls(binary_path))

print(f"Found {len(ground_truth)} syscall instructions via objdump.")
print(f"Found {len(metadata)} valid syscall sites in metadata.")

# Match ground truth to metadata within 64 bytes
true_positives = 0
unmatched_gt = []
matched_metadata = set()

for gt in ground_truth:
    best_match = None
    best_dist = 64
    for i, md in enumerate(metadata):
        if i in matched_metadata: continue
        dist = abs(gt - md)
        if dist < best_dist:
            best_dist = dist
            best_match = i
    if best_match is not None:
        true_positives += 1
        matched_metadata.add(best_match)
    else:
        unmatched_gt.append(gt)

false_positives = len(metadata) - true_positives
false_negatives = len(ground_truth) - true_positives

precision = true_positives / len(metadata) if len(metadata) > 0 else 0
recall = true_positives / len(ground_truth) if len(ground_truth) > 0 else 0

print("\n### Experiment 2: Ground Truth Metrics\n")
print(f"- **True Positives (Match within 64 bytes):** {true_positives}")
print(f"- **False Positives (In metadata but not in binary):** {false_positives}")
print(f"- **False Negatives (In binary but missed by metadata):** {false_negatives}")
print(f"\n**Precision:** {precision:.4f} ({precision*100:.2f}%)")
print(f"**Recall:** {recall:.4f} ({recall*100:.2f}%)")
