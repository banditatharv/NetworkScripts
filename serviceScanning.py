import os
import sys
import argparse
import subprocess
import signal
import time
from datetime import datetime
from threading import Thread, Lock
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

start_time = datetime.now()
tmux_sessions = []  # Track active tmux sessions for cleanup
console = Console()
lock = Lock()

def cleanup_tmux_sessions(sig, frame):
    console.print("\n[bold red]Scan interrupted! Cleaning up tmux sessions...[/]")
    for session in tmux_sessions:
        subprocess.run(f"tmux kill-session -t {session}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sys.exit(1)

signal.signal(signal.SIGINT, cleanup_tmux_sessions)

# Handle graceful exit and session cleanup
def signal_handler(sig, frame):
    console.print("\n[bold red]Interrupted. Cleaning up tmux sessions...[/]")
    sessions = subprocess.run("tmux list-sessions -F '#S'", shell=True, stdout=subprocess.PIPE).stdout.decode().splitlines()
    for session in sessions:
        if session.startswith("svcscan_"):
            subprocess.run(f"tmux kill-session -t {session}", shell=True)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def run_tmux_nmap(ip, ports, output_dir, session_name, progress):
    start_time = datetime.now()
    with lock:
        progress.console.line()
        progress.console.print(f"[green][+] Started scanning {ip}:{ports} at {start_time.strftime('%H:%M:%S')}[/]")



    output_path = os.path.join(output_dir, ip)
    os.makedirs(output_dir, exist_ok=True)
    tmux_sessions.append(session_name)
    cmd = (
        f"tmux new-session -d -s {session_name} "
        f"'sudo nmap -v -p {ports} {ip} -Pn -sSCV -A -oA {output_path}; tmux kill-session -t {session_name}'"
    )
    subprocess.run(cmd, shell=True)


def parse_input_file(path):
    ip_port_list = []
    with open(path, 'r') as f:
        for line in f:
            if ':' in line:
                ip, port_str = line.strip().split(':')
                ip = ip.strip()
                ports = port_str.strip().replace(' ', '')
                ip_port_list.append((ip, ports))
    return ip_port_list


def worker(ip_port_list, output_dir, max_parallel):
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn()
    )
    task = progress.add_task("Scanning IPs...", total=len(ip_port_list))

    active_sessions = []
    ip_index = 0

    start_script_time = datetime.now()
    console.print(f"[bold green]\n[Started at {start_script_time.strftime('%H:%M:%S')}]\n[/]")

    with progress:
        while ip_index < len(ip_port_list) or active_sessions:
            for session in active_sessions[:]:
                result = subprocess.run(f"tmux has-session -t {session}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode != 0:
                    active_sessions.remove(session)
                    progress.advance(task)
                    with lock:
                        progress.console.line()
                        progress.console.print(f"[cyan][✔] Completed scanning {session.replace('svcscan_', '').replace('_', ':')}[/]")


            while ip_index < len(ip_port_list) and len(active_sessions) < max_parallel:
                ip, ports = ip_port_list[ip_index]
                session_name = f"svcscan_{ip.replace('.', '_')}_{ports.replace(',', '_')}"
                run_tmux_nmap(ip, ports, output_dir, session_name,progress)
                active_sessions.append(session_name)
                ip_index += 1

            time.sleep(1)

    end_script_time = datetime.now()
    progress.console.line()
    progress.console.print(f"[bold green]\n[Completed at {end_script_time.strftime('%H:%M:%S')}]\n[/]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Service & Version Nmap Scanner with Tmux and Rich")
    parser.add_argument("-i", "--input", help="Path to file with ip:port list (one per line)")
    parser.add_argument("--ip", help="Single IP address")
    parser.add_argument("--ports", help="Ports for single IP (comma separated)")
    parser.add_argument("-o", "--output", required=True, help="Directory to save Nmap output")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Number of concurrent scans")
    args = parser.parse_args()

    ip_port_list = []

    if args.input:
        if not os.path.exists(args.input):
            console.print(f"[bold red]Input file {args.input} not found.[/]")
            sys.exit(1)
        ip_port_list = parse_input_file(args.input)
    elif args.ip and args.ports:
        ip_port_list = [(args.ip, args.ports)]
    else:
        console.print("[bold red]Either --input or both --ip and --ports must be provided.[/]")
        sys.exit(1)

    worker(ip_port_list, args.output, args.threads)