#!/usr/bin/env python3
"""
Example usage patterns for Daily IOC Puller
Run this to see what the output looks like
"""

import subprocess
import sys

def run_command(desc, cmd):
    print(f"\n{'='*80}")
    print(f"  {desc}")
    print(f"{'='*80}")
    subprocess.run([sys.executable, "daily_ioc_puller.py"] + cmd.split())

if __name__ == "__main__":
    print("""
Daily IOC Puller - Example Usage Patterns
==========================================

Make sure you have your API keys set as environment variables:
  - ABUSECH_AUTH_KEY
  - OTX_API_KEY

Uncomment the examples below to run them.
""")

    # Example 1: Quick summary
    run_command("Example 1: Quick Summary (Fast Overview)", "--summary")
    
    # Example 2: List all families
    # run_command("Example 2: List All Malware Families", "--list")
    
    # Example 3: Search for specific malware
    # run_command("Example 3: Search for Specific Malware (e.g., remcos)", "--filter remcos")
    
    # Example 4: Full detailed report (default)
    # run_command("Example 4: Full Detailed Report", "")
