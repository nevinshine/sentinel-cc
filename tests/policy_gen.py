#!/usr/bin/env python3
# policy_gen_v3.py
# Phase 3: CFI Policy Extractor
# Extracts Syscall Offset AND Valid Caller Range (safe_logger)
import sys
import subprocess
import re

def extract_cfi_policy(binary_path, output_file):
    print(f"[*] Disassembling {binary_path} for CFI policy...")

    cmd = ["objdump", "-d", "-M", "intel", binary_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    lines = result.stdout.splitlines()
    
    # We need:
    # 1. Syscall Offset (inside do_write_shared)
    # 2. safe_logger Start Offset
    # 3. safe_logger End Offset
    
    syscall_offset = None
    safe_start = None
    safe_end = None
    
    current_function = None
    
    for line in lines:
        # Detect function start
        func_match = re.search(r'([0-9a-f]+) <([^>]+)>:', line)
        if func_match:
            addr = int(func_match.group(1), 16)
            name = func_match.group(2)
            current_function = name
            
            if name == "safe_logger":
                safe_start = addr
            continue
            
        # Detect function end (start of next function)
        # Assuming safe_logger is followed by another function or we track size.
        # Simple scan: if we have safe_start and hit another function, close it.
        if safe_start and not safe_end and current_function != "safe_logger":
             # We moved past safe_logger
             # The previous line was the last instruction?? 
             # Rough approximation: current addr is end.
             # Actually, simpler: parse line logic. If we see a new header and safe_start is set...
             # Handle '4f0:' format by stripping colon
             parts = line.split()
             if parts:
                 safe_end = int(parts[0].replace(':', ''), 16)
             else:
                 safe_end = None

        # Detect syscall in SHARED function
        if current_function == "do_write_shared" and "syscall" in line:
            parts = line.strip().split(':')
            syscall_offset = int(parts[0], 16)
            print(f"[+] Found SYSCALL in {current_function} at 0x{syscall_offset:x}")

    # Determine safe_end more reliably by second pass or better parsing
    # Let's re-parse for safe_logger size
    
    cflow_safe = False
    for line in lines:
        if "<safe_logger>:" in line:
            cflow_safe = True
            parts = line.split()
            safe_start = int(parts[0], 16)
            continue
        
        if cflow_safe:
            # Check if this line looks like start of next function
            if re.search(r'^[0-9a-f]+ <[^>]+>:', line):
                parts = line.split()
                safe_end = int(parts[0], 16)
                cflow_safe = False
                break
            # Update scan tail
            try:
                parts = line.strip().split(':')
                if len(parts) > 1:
                    last_addr = int(parts[0], 16)
                    # safe_end approx
            except:
                pass
    
    if safe_end is None and cflow_safe:
        # End of file?
        safe_end = safe_start + 0x100 # Default size if last function

    if syscall_offset is None or safe_start is None:
        print("[-] Failed to find syscall or safe_logger")
        sys.exit(1)

    print(f"[+] Policy: Syscall 0x{syscall_offset:x} requires Caller in [0x{safe_start:x}, 0x{safe_end:x}]")
    
    with open(output_file, 'w') as out:
        # Format: SyscallOffset CallerStart CallerEnd
        out.write(f"{syscall_offset:x} {safe_start:x} {safe_end:x}")

if __name__ == "__main__":
    extract_cfi_policy(sys.argv[1], sys.argv[2])
