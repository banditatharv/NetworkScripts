#!/usr/bin/env python3
"""
Complete Nmap-based Subnet Sweep Workflow
Scans subnets using nmap and automatically generates consolidated report
"""

import subprocess
import argparse
import sys
import os
from datetime import datetime

class NmapSubnetSweepWorkflow:
    def __init__(self, subnets_file, output_dir, timing, report_format):
        self.subnets_file = subnets_file
        self.output_dir = output_dir
        self.timing = timing
        self.report_format = report_format
        self.report_name = f"subnet_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def run_scan(self):
        """Run the nmap-based subnet sweep scan"""
        print(f"\n{'='*70}")
        print("STEP 1: NMAP-BASED SUBNET SCANNING")
        print(f"{'='*70}\n")
        
        scan_script = "nmap_subnet_sweep.py"
        if not os.path.exists(scan_script):
            print(f"[!] Error: {scan_script} not found in current directory")
            return False
        
        cmd = [
            "python3", scan_script,
            "-f", self.subnets_file,
            "-o", self.output_dir,
            "-t", self.timing
        ]
        
        print(f"[*] Running: {' '.join(cmd)}\n")
        
        try:
            result = subprocess.run(cmd, check=True)
            if result.returncode == 0:
                print(f"\n[+] Scanning completed successfully!")
                return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Scanning failed with error: {e}")
            return False
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return False
    
    def generate_report(self):
        """Generate consolidated report"""
        print(f"\n{'='*70}")
        print("STEP 2: REPORT GENERATION")
        print(f"{'='*70}\n")
        
        report_script = "generate_report.py"
        if not os.path.exists(report_script):
            print(f"[!] Error: {report_script} not found in current directory")
            return False
        
        cmd = [
            "python3", report_script,
            "-d", self.output_dir,
            "-o", self.report_name,
            "-f", self.report_format
        ]
        
        print(f"[*] Running: {' '.join(cmd)}\n")
        
        try:
            result = subprocess.run(cmd, check=True)
            if result.returncode == 0:
                print(f"\n[+] Report generation completed successfully!")
                return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Report generation failed with error: {e}")
            return False
    
    def run(self):
        """Execute complete workflow"""
        print(f"\n{'#'*70}")
        print("#" + " "*68 + "#")
        print("#" + " NMAP-BASED SUBNET SWEEP & REPORT WORKFLOW ".center(68) + "#")
        print("#" + " "*68 + "#")
        print(f"{'#'*70}\n")
        
        print(f"Configuration:")
        print(f"  - Subnets File: {self.subnets_file}")
        print(f"  - Output Directory: {self.output_dir}")
        print(f"  - Nmap Timing: {self.timing}")
        print(f"  - Report Format: {self.report_format}")
        print(f"  - Report Name: {self.report_name}")
        
        # Step 1: Scan
        if not self.run_scan():
            print("\n[!] Workflow failed at scanning stage")
            return False
        
        # Step 2: Generate report
        if not self.generate_report():
            print("\n[!] Workflow failed at report generation stage")
            return False
        
        # Success summary
        print(f"\n{'='*70}")
        print("WORKFLOW COMPLETED SUCCESSFULLY!")
        print(f"{'='*70}\n")
        
        print("Generated Files:")
        print(f"  1. Scan Results: {self.output_dir}/")
        if self.report_format in ['csv', 'both']:
            print(f"  2. CSV Report: {self.report_name}.csv")
        if self.report_format in ['excel', 'both']:
            print(f"  3. Excel Report: {self.report_name}.xlsx")
        
        print(f"\n{'='*70}\n")
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Complete nmap-based subnet sweep workflow with automated reporting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script performs a complete nmap-based subnet sweep workflow:
  1. Scans all subnets using nmap's comprehensive host discovery
  2. Automatically generates consolidated CSV/Excel report

Examples:
  python3 nmap_workflow.py -f subnets.txt
  python3 nmap_workflow.py -f subnets.txt -t T5 -r excel
  sudo python3 nmap_workflow.py -f subnets.txt -t T4 -r both

Timing Templates:
  T3 - Normal (balanced)
  T4 - Aggressive (recommended, default)
  T5 - Insane (very fast)

Note: Run with sudo for better accuracy
        """
    )
    
    parser.add_argument('-f', '--file', 
                       required=True,
                       help='File containing list of subnets')
    parser.add_argument('-o', '--output', 
                       default='scan_results',
                       help='Output directory for scan results (default: scan_results)')
    parser.add_argument('-t', '--timing',
                       default='T4',
                       choices=['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
                       help='Nmap timing template (default: T4)')
    parser.add_argument('-r', '--report-format',
                       choices=['csv', 'excel', 'both'],
                       default='both',
                       help='Report format (default: both)')
    
    args = parser.parse_args()
    
    # Validate subnets file exists
    if not os.path.exists(args.file):
        print(f"[!] Error: Subnets file '{args.file}' not found")
        sys.exit(1)
    
    # Run workflow
    workflow = NmapSubnetSweepWorkflow(
        args.file,
        args.output,
        args.timing,
        args.report_format
    )
    
    success = workflow.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Workflow interrupted by user")
        sys.exit(1)
