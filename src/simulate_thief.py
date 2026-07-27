#!/usr/bin/env python3
"""
Simulates a 'resource thief' process for testing the detector.
Run this in a SECOND terminal while the detector is running.

Scenario 1: Rapid file access (exfiltration simulation)
Scenario 2: Sensitive file snooping
"""

import os
import sys
import time
import argparse

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
RESET = "\033[0m"

def scenario_rapid_read(count: int):
    """Open many files very quickly — triggers rate-based alert."""
    print(f"{CYAN}[Thief] Scenario 1: Rapid file access ({count} files){RESET}")
    files_opened = 0
    for root, dirs, files in os.walk("/usr/lib"):
        for name in files:
            try:
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    f.read(1)
                files_opened += 1
                if files_opened >= count:
                    print(f"{RED}[Thief] Opened {files_opened} files. Check the detector!{RESET}")
                    return
            except (PermissionError, OSError):
                continue

def scenario_sensitive_snoop():
    """Try to read known sensitive files — triggers path-based alert."""
    print(f"{CYAN}[Thief] Scenario 2: Sensitive file snooping{RESET}")
    targets = [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/version",
        "/proc/cpuinfo",
    ]
    for path in targets:
        try:
            with open(path) as f:
                first_line = f.readline().strip()
            print(f"{GREEN}[Thief] Read {path}: {first_line[:60]}{RESET}")
        except PermissionError:
            print(f"{RED}[Thief] Permission denied: {path}{RESET}")
        time.sleep(0.3)

def main():
    parser = argparse.ArgumentParser(description="Simulated resource thief for BPF detector testing")
    parser.add_argument("scenario", choices=["rapid", "snoop", "both"],
                        help="Which attack scenario to simulate")
    parser.add_argument("--count", type=int, default=100,
                        help="Number of files to open in 'rapid' scenario (default: 100)")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*50}{RESET}")
    print(f"{BOLD}  Resource Thief Simulator{RESET}")
    print(f"{BOLD}  PID: {os.getpid()}{RESET}")
    print(f"{BOLD}{'='*50}{RESET}\n")

    if args.scenario in ("rapid", "both"):
        scenario_rapid_read(args.count)
    if args.scenario in ("snoop", "both"):
        scenario_sensitive_snoop()

    print(f"\n{GREEN}[Thief] Done. Check detector output!{RESET}")

if __name__ == "__main__":
    main()
