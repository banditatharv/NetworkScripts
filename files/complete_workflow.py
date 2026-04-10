#!/usr/bin/env python3
"""
Complete Subnet Sweep Workflow
Scans subnets and automatically generates consolidated report
"""

import subprocess
import argparse
import sys
import os
from datetime import datetime

class SubnetSweepWorkflow:
    def __init__(self, subnets_file, output_dir, threads, report_format):
        self.subnets_file = subnets_file
        self.output_dir = output_dir
        self.threads = threads
        self.report_format = report_format
        self.report_name = f"subnet_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def run_scan(self):
        """Run the subnet sweep scan"""
        print(f"\n{'='*70}")
        print("STEP 1: SUBNET SCANNING")
        print(f"{'='*70}\n")
        
        scan_script = "advanced_subnet_sweep.py"
        if not os.path.exists(scan_script):
            print(f"[!] Error: {scan_script} not found in current directory")
            return False
        
        cmd = [
            "python3", scan_script,
            "-f", self.subnets_file,
            "-o", self.output_dir,
            "-t", str(self.threads)
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
        print("#" + " COMPLETE SUBNET SWEEP & REPORT WORKFLOW ".center(68) + "#")
        print("#" + " "*68 + "#")
        print(f"{'#'*70}\n")
        
        print(f"Configuration:")
        print(f"  - Subnets File: {self.subnets_file}")
        print(f"  - Output Directory: {self.output_dir}")
        print(f"  - Threads: {self.threads}")
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
        description='Complete subnet sweep workflow with automated reporting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script performs a complete subnet sweep workflow:
  1. Scans all subnets for alive hosts
  2. Automatically generates consolidated CSV/Excel report

Examples:
  python3 complete_workflow.py -f subnets.txt
  python3 complete_workflow.py -f subnets.txt -t 100 -r excel
  python3 complete_workflow.py -f subnets.txt -o results -t 75 -r both

Workflow Steps:
  1. Reads subnets from input file
  2. Scans each subnet using multiple detection methods
  3. Saves detailed results per subnet
  4. Generates consolidated CSV/Excel report
  5. Provides summary statistics
        """
    )
    
    parser.add_argument('-f', '--file', 
                       required=True,
                       help='File containing list of subnets')
    parser.add_argument('-o', '--output', 
                       default='scan_results',
                       help='Output directory for scan results (default: scan_results)')
    parser.add_argument('-t', '--threads', 
                       type=int,
                       default=50,
                       help='Number of scanning threads (default: 50)')
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
    workflow = SubnetSweepWorkflow(
        args.file,
        args.output,
        args.threads,
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
