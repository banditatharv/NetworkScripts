#!/usr/bin/env python3
"""
Nuclei Parallel Scanner with Tmux
Scans IP:Port pairs concurrently using nuclei in tmux sessions
With optional port scan output conversion
"""

import subprocess
import time
import signal
import sys
from datetime import datetime
from queue import Queue
from pathlib import Path

# Global list to track tmux sessions (for cleanup)
tmux_sessions = []

def cleanup_tmux_sessions(sig=None, frame=None):
    """Cleanup function for signal handler - kills all tracked tmux sessions"""
    print(f"\n[!] Scan interrupted! Cleaning up tmux sessions...")
    for session in tmux_sessions:
        subprocess.run(
            f"tmux kill-session -t {session}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"  Killed: {session}")
    sys.exit(1)


# Register signal handler for Ctrl+C
signal.signal(signal.SIGINT, cleanup_tmux_sessions)


def convert_port_scan_to_nuclei(input_file):
    """Convert port scan output format to nuclei format"""
    output_file = "nuclei_scope.txt"
    output_lines = []
    unique_ips = set()

    print(f"\n[*] Converting port scan output to nuclei format...")
    print(f"[*] Input file: {input_file}")

    try:
        with open(input_file, "r") as infile:
            for line in infile:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                ip, ports = line.split(":", 1)
                ports = ports.split(",")
                unique_ips.add(ip)
                for port in ports:
                    port = port.strip()
                    if port:
                        output_lines.append(f"{ip}:{port}")
    except FileNotFoundError:
        print(f"[!] Error: File '{input_file}' not found.")
        return None

    # Write to output file
    with open(output_file, "w") as outfile:
        for line in output_lines:
            outfile.write(line + "\n")

    print(f"[+] Conversion complete!")
    print(f"[+] Original IPs: {len(unique_ips)}")
    print(f"[+] Total IP:Port combinations: {len(output_lines)}")
    print(f"[+] Saved to: {output_file}\n")

    return output_file


def read_targets_from_file(file_path):
    """Read IP:Port pairs from file"""
    try:
        with open(file_path, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
        return targets
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        sys.exit(1)


def sanitize_session_name(target):
    """Convert IP:Port to tmux-friendly session name"""
    # Replace colons and periods with hyphens
    sanitized = target.replace(':', '-').replace('.', '-')
    return f"nuclei-{sanitized}"


def create_tmux_session(session_name, target, log_file):
    """Create tmux session and run nuclei scan"""
    try:
        # Create new tmux session
        subprocess.run(
            ['tmux', 'new-session', '-d', '-s', session_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Build nuclei command
        nuclei_command = f'nuclei -u {target} -v -me Nuclei-results && exit'

        # Send command to tmux session
        subprocess.run(
            ['tmux', 'send-keys', '-t', session_name, nuclei_command, 'C-m'],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Add to global tracking list
        tmux_sessions.append(session_name)

        # Log the start
        start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(log_file, 'a') as f:
            f.write(f"[{start_time}] Started scan on {target} in tmux session {session_name}\n")

        print(f"[+] Started scan on {target} (session: {session_name})")
        return True

    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to start session {session_name}: {e}")
        return False


def kill_tmux_session(session_name, log_file, target):
    """Kill tmux session and log completion"""
    try:
        subprocess.run(
            ['tmux', 'kill-session', '-t', session_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Remove from global tracking list
        if session_name in tmux_sessions:
            tmux_sessions.remove(session_name)

        # Log the completion
        end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(log_file, 'a') as f:
            f.write(f"[{end_time}] Completed scan on {target} in tmux session {session_name}\n")

        print(f"[✔] Completed scan on {target}")

    except subprocess.CalledProcessError:
        pass  # Session might already be dead


def is_session_active(session_name):
    """Check if tmux session is still active"""
    try:
        result = subprocess.run(
            ['tmux', 'has-session', '-t', session_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False


def run_parallel_scan(targets, max_concurrent_sessions, log_file):
    """Run nuclei scans in parallel using work queue approach"""
    # Create queue and tracking
    target_queue = Queue()
    for target in targets:
        target_queue.put(target)

    running_sessions = {}  # session_name -> target
    completed_count = 0
    failed_count = 0

    print(f"\n[*] Starting parallel scan with {max_concurrent_sessions} concurrent sessions")
    print(f"[*] Total targets to scan: {len(targets)}\n")

    # Start initial batch of sessions
    print(f"[+] Starting initial batch of {min(max_concurrent_sessions, len(targets))} sessions...")

    while not target_queue.empty() or running_sessions:
        # Start new sessions up to max_concurrent_sessions
        while not target_queue.empty() and len(running_sessions) < max_concurrent_sessions:
            target = target_queue.get()
            session_name = sanitize_session_name(target)

            if create_tmux_session(session_name, target, log_file):
                running_sessions[session_name] = target
            else:
                failed_count += 1

        # Wait a bit before checking status
        time.sleep(5)

        # Check for completed sessions
        for session_name, target in list(running_sessions.items()):
            if not is_session_active(session_name):
                # Session completed
                kill_tmux_session(session_name, log_file, target)
                del running_sessions[session_name]
                completed_count += 1

        # Show progress
        total_processed = completed_count + failed_count
        percentage = (total_processed / len(targets) * 100) if targets else 0
        print(f"\r[*] Progress: {total_processed}/{len(targets)} "
              f"({percentage:.1f}%) | Active: {len(running_sessions)} | "
              f"Completed: {completed_count} | Failed: {failed_count}",
              end='', flush=True)

    print()  # New line after progress

    return completed_count, failed_count


def print_summary(completed, failed, total_targets, log_file, start_time, end_time):
    """Print scan summary"""
    print("\n" + "="*80)
    print("SCAN SUMMARY")
    print("="*80)
    print(f"Total targets:        {total_targets}")
    print(f"Successfully scanned: {completed}")
    print(f"Failed:               {failed}")
    print(f"Success rate:         {completed/total_targets*100:.1f}%" if total_targets > 0 else "Success rate:         N/A")
    print(f"Duration:             {end_time - start_time}")
    print(f"\nLog file:             {log_file}")
    print("="*80 + "\n")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("           NUCLEI PARALLEL SCANNER")
    print("="*80 + "\n")

    # Ask if user wants to convert port scan output
    while True:
        convert_choice = input("[?] Do you want to convert port scan output to nuclei format? (y/n): ").strip().lower()
        if convert_choice in ['y', 'n']:
            break
        print("[!] Please enter 'y' or 'n'")

    # Get the target file path
    if convert_choice == 'y':
        # Ask for port scan output file
        port_scan_file = input("[?] Enter the path to port scan output file: ").strip()
        target_file = convert_port_scan_to_nuclei(port_scan_file)

        if target_file is None:
            print("[!] Conversion failed. Exiting.")
            sys.exit(1)
    else:
        # Ask for already formatted nuclei file
        target_file = input("[?] Enter the path to nuclei formatted file (IP:Port pairs): ").strip()

    # Read targets from file
    targets = read_targets_from_file(target_file)

    if not targets:
        print("[!] No targets found in file")
        sys.exit(1)

    print(f"[+] Loaded {len(targets)} targets from {target_file}")

    # Get max concurrent sessions
    try:
        max_concurrent = input("[?] Enter max concurrent sessions (default 5, max 20): ").strip()
        max_concurrent = int(max_concurrent) if max_concurrent else 5

        # Validate range
        if max_concurrent < 1:
            print("[!] Setting minimum to 1")
            max_concurrent = 1
        elif max_concurrent > 20:
            print("[!] Limiting to 20 concurrent sessions")
            max_concurrent = 20

    except ValueError:
        print("[!] Invalid input, using default: 5")
        max_concurrent = 5

    # Create log file with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f"nuclei_scan_log_{timestamp}.txt"

    # Create output directory for results
    output_dir = Path("nuclei_results")
    output_dir.mkdir(exist_ok=True)

    print(f"\n[+] Log file: {log_file}")
    print(f"[+] Results will be saved in: nuclei_results/")
    print(f"[+] Max concurrent sessions: {max_concurrent}\n")

    # Record start time
    scan_start_time = datetime.now()

    # Initialize log file
    with open(log_file, 'a') as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"Nuclei Scan Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Source File: {target_file}\n")
        f.write(f"Total Targets: {len(targets)}\n")
        f.write(f"Max Concurrent Sessions: {max_concurrent}\n")
        f.write(f"{'='*80}\n\n")

    try:
        # Run parallel scan
        completed, failed = run_parallel_scan(targets, max_concurrent, log_file)

        # Record end time
        scan_end_time = datetime.now()

        # Finalize log file
        with open(log_file, 'a') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"Nuclei Scan Completed: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {scan_end_time - scan_start_time}\n")
            f.write(f"Completed: {completed}\n")
            f.write(f"Failed: {failed}\n")
            f.write(f"{'='*80}\n")

        # Print summary
        print_summary(completed, failed, len(targets), log_file, scan_start_time, scan_end_time)

        print("[+] Scan complete!")
        print(f"[+] Converted file saved as: nuclei_scope.txt\n")

    except KeyboardInterrupt:
        # Signal handler will catch this
        sys.exit(0)
    finally:
        # Clear global session list on normal exit
        tmux_sessions.clear()