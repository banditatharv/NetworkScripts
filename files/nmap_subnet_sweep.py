#!/usr/bin/env python3
"""
Advanced Subnet Sweep Script with Nmap
Efficient host discovery using nmap's comprehensive techniques
Saves results in subnet-wise text files for Excel/CSV reporting
"""

import ipaddress
import subprocess
import argparse
import os
from datetime import datetime
import re
import sys

class SubnetScanner:
    def __init__(self, subnets_file, output_dir="scan_results", timing="T4"):
        self.subnets_file = subnets_file
        self.output_dir = output_dir
        self.timing = timing
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def run_nmap_scan(self, target, is_subnet=False):
        """
        Run nmap with comprehensive host discovery techniques
        Uses multiple ICMP, TCP, and UDP methods for maximum detection
        """
        try:
            # Build nmap command with comprehensive host discovery
            cmd = [
                'nmap',
                '-sn',  # Ping scan (no port scan)
                '-v',   # Verbose
                f'-{self.timing}',  # Timing template
                '-PE',  # ICMP Echo
                '-PP',  # ICMP Timestamp
                '-PM',  # ICMP Netmask
                '-PS21,22,23,25,80,135,139,443,445,3306,3389,8080',  # TCP SYN to common ports
                '-PA80,443,3389',  # TCP ACK to common ports
                '-PU53,161',  # UDP ping
                '-n',   # No DNS resolution (faster)
                str(target)
            ]
            
            print(f"[*] Running: {' '.join(cmd)}")
            
            # Run nmap
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            print(f"[!] Scan timeout for {target}")
            return None, "Timeout", -1
        except Exception as e:
            print(f"[!] Error scanning {target}: {e}")
            return None, str(e), -1
    
    def parse_nmap_output(self, stdout, stderr):
        """
        Parse nmap output to extract alive hosts
        Returns list of (ip, status) tuples
        """
        alive_hosts = []
        
        # Combine stdout and stderr for complete output
        full_output = f"{stdout}\n{stderr}" if stderr else stdout
        
        # Pattern to match "Nmap scan report for X.X.X.X"
        # and the following line with "Host is up"
        lines = full_output.split('\n')
        
        for i, line in enumerate(lines):
            if 'Nmap scan report for' in line:
                # Extract IP address
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    
                    # Check next few lines for "Host is up"
                    status = "unknown"
                    for j in range(i+1, min(i+5, len(lines))):
                        if 'Host is up' in lines[j]:
                            status = "up"
                            # Try to extract latency
                            latency_match = re.search(r'latency\)?\s*\.?\s*$', lines[j])
                            if latency_match:
                                status = f"up - {lines[j].split('(')[1].split(')')[0] if '(' in lines[j] else 'detected'}"
                            break
                    
                    if status != "unknown":
                        alive_hosts.append((ip, status))
                        print(f"[+] {ip} is ALIVE - {status}")
        
        return alive_hosts
    
    def scan_subnet(self, subnet):
        """Scan a single subnet"""
        print(f"\n[*] Scanning subnet: {subnet}")
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            print(f"[*] Network: {network}")
            print(f"[*] Total addresses: {network.num_addresses}")
            print(f"[*] Network address: {network.network_address}")
            print(f"[*] Broadcast address: {network.broadcast_address}")
            
            start_time = datetime.now()
            
            # Run nmap scan
            stdout, stderr, returncode = self.run_nmap_scan(subnet, is_subnet=True)
            
            if stdout is None:
                print(f"[!] Scan failed for {subnet}")
                return []
            
            # Parse results
            alive_hosts = self.parse_nmap_output(stdout, stderr)
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            print(f"\n[+] Found {len(alive_hosts)} alive host(s) in {subnet}")
            print(f"[*] Scan duration: {duration}")
            
            # Save results
            self.save_results(subnet, network, alive_hosts, stdout, stderr, duration, start_time)
            
            return alive_hosts
            
        except ValueError as e:
            print(f"[!] Invalid subnet format: {subnet} - {e}")
            return []
        except Exception as e:
            print(f"[!] Error scanning {subnet}: {e}")
            return []
    
    def save_results(self, subnet, network, alive_hosts, stdout, stderr, duration, start_time):
        """Save results to subnet-specific files"""
        # Create safe filename from subnet
        subnet_name = str(subnet).replace('/', '_').replace(':', '-')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Detailed results file
        detailed_file = f"{self.output_dir}/{subnet_name}_{timestamp}.txt"
        
        with open(detailed_file, 'w') as f:
            f.write(f"Subnet Scan Results\n")
            f.write(f"{'='*60}\n")
            f.write(f"Subnet: {subnet}\n")
            f.write(f"Scan Date: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {duration}\n")
            f.write(f"Total Alive Hosts: {len(alive_hosts)}\n")
            f.write(f"\nNetwork Information:\n")
            f.write(f"- Network address: {network.network_address}\n")
            f.write(f"- Broadcast address: {network.broadcast_address}\n")
            f.write(f"- Subnet mask: {network.netmask}\n")
            f.write(f"- Total addresses: {network.num_addresses}\n")
            f.write(f"{'='*60}\n\n")
            
            if alive_hosts:
                f.write("Alive Hosts:\n")
                f.write(f"{'-'*60}\n")
                for ip, status in alive_hosts:
                    f.write(f"{ip}\t\t{status}\n")
                f.write(f"\n{'-'*60}\n\n")
            
            f.write("Complete Nmap Output:\n")
            f.write(f"{'='*60}\n")
            f.write(stdout)
            if stderr:
                f.write(f"\n\nNmap Warnings/Errors:\n")
                f.write(f"{'-'*60}\n")
                f.write(stderr)
        
        # IP-only file for easy import
        ip_only_file = f"{self.output_dir}/{subnet_name}_{timestamp}_ips_only.txt"
        with open(ip_only_file, 'w') as f:
            for ip, _ in alive_hosts:
                f.write(f"{ip}\n")
        
        print(f"\n[*] Results saved to:")
        print(f"    - {detailed_file}")
        print(f"    - {ip_only_file}")
    
    def run(self):
        """Main execution method"""
        print(f"\n{'='*60}")
        print(f"Advanced Subnet Sweep Scanner (Nmap-based)")
        print(f"{'='*60}")
        print(f"Detection Methods:")
        print(f"  - ICMP Echo, Timestamp, Netmask")
        print(f"  - TCP SYN to common ports")
        print(f"  - TCP ACK probes")
        print(f"  - UDP ping")
        print(f"  - Timing: {self.timing}")
        print(f"{'='*60}\n")
        
        # Check if nmap is installed
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[!] Error: nmap is not installed or not in PATH")
            print("[!] Please install nmap: sudo apt install nmap")
            sys.exit(1)
        
        # Read subnets from file
        try:
            with open(self.subnets_file, 'r') as f:
                subnets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Error: Subnets file '{self.subnets_file}' not found")
            sys.exit(1)
        
        if not subnets:
            print("[!] No subnets found in file")
            sys.exit(1)
        
        print(f"[*] Loaded {len(subnets)} subnet(s) to scan")
        print(f"[*] Output directory: {self.output_dir}\n")
        
        # Scan each subnet
        total_alive = 0
        total_start = datetime.now()
        
        for subnet in subnets:
            try:
                alive_hosts = self.scan_subnet(subnet)
                total_alive += len(alive_hosts)
            except Exception as e:
                print(f"[!] Error processing {subnet}: {e}")
        
        total_duration = datetime.now() - total_start
        
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Total alive hosts discovered: {total_alive}")
        print(f"Total scan time: {total_duration}")
        print(f"Results saved in: {self.output_dir}/")
        print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Subnet Sweep using Nmap - Detect alive hosts efficiently',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nmap_subnet_sweep.py -f subnets.txt
  python3 nmap_subnet_sweep.py -f subnets.txt -o results -t T5
  sudo python3 nmap_subnet_sweep.py -f subnets.txt -t T4
  
Timing Templates:
  T0 (Paranoid)  - Very slow, for IDS evasion
  T1 (Sneaky)    - Slow
  T2 (Polite)    - Slower than normal
  T3 (Normal)    - Default nmap timing
  T4 (Aggressive)- Faster, recommended (default)
  T5 (Insane)    - Very fast, may miss hosts

Subnets file format (one subnet per line):
  192.168.1.0/24
  10.0.0.0/16
  172.16.0.0/12
  
Note: Run with sudo for better accuracy (ARP ping, etc.)
        """
    )
    
    parser.add_argument('-f', '--file', required=True, 
                       help='File containing list of subnets (one per line)')
    parser.add_argument('-o', '--output', default='scan_results', 
                       help='Output directory for results (default: scan_results)')
    parser.add_argument('-t', '--timing', default='T4',
                       choices=['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
                       help='Nmap timing template (default: T4)')
    
    args = parser.parse_args()
    
    scanner = SubnetScanner(args.file, args.output, args.timing)
    scanner.run()


if __name__ == "__main__":
    main()
