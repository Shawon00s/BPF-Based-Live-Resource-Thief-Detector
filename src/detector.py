#!/usr/bin/env python3
"""
BPF-Based Live Resource Thief Detector
OS Course Project

Architecture:
  Kernel Space (ebpf_sensor.c)  →  eBPF Maps  →  User Space (this file)
"""

import os
import sys
import time
import ctypes
import signal
import datetime
from collections import defaultdict
from bcc import BPF

# ─── ANSI Color Codes ─────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
BLUE   = "\033[94m"

# ─── Detection Thresholds ─────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/", "/.ssh/", "/proc/", "/root/",
    "/home/", ".env", ".pem", ".key", "id_rsa",
    "credentials", "secret", "token", "password",
]

FILE_READ_THRESHOLD  = 50    # alerts if a PID opens >50 files per second
WINDOW_SECONDS       = 1     # time window for rate-based checks
WHITELIST_PROCESSES  = {     # known-good processes to suppress noise
    "systemd", "bash", "python3", "sshd", "cron",
    "apt", "dpkg", "snap", "snapd", "code", "code-tunnel",
    "ThreadPoolSingl", "gmain", "pool-",              # VS Code / IDE threads
    "electron", "node", "typescript",
}

# ─── State ────────────────────────────────────────────────────────────────────
file_counts     = defaultdict(int)   # pid → count this window
last_reset      = time.time()
alerted_pids    = set()              # avoid duplicate alerts
event_log       = []                 # for report generation

# ─── Helpers ─────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║       BPF-Based Live Resource Thief Detector             ║
║       Kernel: {os.uname().release:<20}                  ║
║       Started: {datetime.datetime.now().strftime('%H:%M:%S %d-%b-%Y'):<20}             ║
╚══════════════════════════════════════════════════════════╝{RESET}
{GREEN}[*] Attaching eBPF probes to kernel syscalls...{RESET}
""")


def is_sensitive(filename: str) -> bool:
    return any(p in filename for p in SENSITIVE_PATHS)


def log_event(level: str, pid: int, comm: str, detail: str):
    ts  = datetime.datetime.now().strftime("%H:%M:%S")
    entry = {"time": ts, "level": level, "pid": pid, "comm": comm, "detail": detail}
    event_log.append(entry)

    color = RED if level == "ALERT" else YELLOW if level == "WARN" else CYAN
    print(f"{color}[{level}]{RESET} {ts} | PID {BOLD}{pid:<6}{RESET} ({comm:<20}) | {detail}")


def reset_counters():
    global file_counts, last_reset
    file_counts.clear()
    last_reset = time.time()


def save_report():
    path = f"/home/sudipto-roy-s-hawon/Downloads/Project/reports/report_{int(time.time())}.txt"
    with open(path, "w") as f:
        f.write("BPF Resource Thief Detector — Session Report\n")
        f.write(f"Generated: {datetime.datetime.now()}\n")
        f.write("=" * 60 + "\n\n")
        for e in event_log:
            f.write(f"[{e['level']}] {e['time']} | PID {e['pid']} ({e['comm']}) | {e['detail']}\n")
    print(f"\n{GREEN}[*] Report saved to: {path}{RESET}")


# ─── eBPF Event Callbacks ─────────────────────────────────────────────────────

def handle_file_event(cpu, data, size):
    global file_counts, last_reset

    event = bpf["file_events"].event(data)
    pid   = event.pid
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    fname = event.filename.decode("utf-8", errors="replace").strip()

    if comm in WHITELIST_PROCESSES:
        return

    # Rate-based detection: reset counter every WINDOW_SECONDS
    now = time.time()
    if now - last_reset >= WINDOW_SECONDS:
        reset_counters()

    file_counts[pid] += 1

    # Alert: sensitive file access
    if is_sensitive(fname):
        log_event("ALERT", pid, comm,
                  f"Accessed sensitive file → {fname}")

    # Alert: high-frequency file access (possible data exfiltration)
    if file_counts[pid] > FILE_READ_THRESHOLD and pid not in alerted_pids:
        alerted_pids.add(pid)
        log_event("ALERT", pid, comm,
                  f"High-speed file access: {file_counts[pid]} files/sec  ← POSSIBLE EXFILTRATION")


def handle_proc_event(cpu, data, size):
    event = bpf["proc_events"].event(data)
    pid   = event.pid
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    fname = event.filename.decode("utf-8", errors="replace").strip()

    if comm in WHITELIST_PROCESSES:
        return

    # Warn about suspicious executables
    suspicious_keywords = ["ncat", "nc", "netcat", "curl", "wget",
                           "python", "perl", "ruby", "bash", "sh",
                           "socat", "reverse", "shell", "exploit"]
    if any(k in fname.lower() for k in suspicious_keywords):
        log_event("WARN", pid, comm, f"Suspicious exec → {fname}")
    else:
        log_event("INFO", pid, comm, f"New process → {fname}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print(f"{RED}[ERROR] Must run as root: sudo python3 detector.py{RESET}")
        sys.exit(1)

    banner()

    # Load and compile the eBPF C program
    sensor_path = os.path.join(os.path.dirname(__file__), "ebpf_sensor.c")
    with open(sensor_path) as f:
        bpf_src = f.read()

    global bpf
    bpf = BPF(text=bpf_src)

    # Attach callbacks
    bpf["file_events"].open_perf_buffer(handle_file_event)
    bpf["proc_events"].open_perf_buffer(handle_proc_event)

    print(f"{GREEN}[+] eBPF probes attached successfully!{RESET}")
    print(f"{CYAN}[*] Monitoring live syscalls... Press Ctrl+C to stop.{RESET}\n")
    print(f"{'─'*70}")
    print(f"{'Level':<8} {'Time':<10} {'PID':<8} {'Process':<22} {'Detail'}")
    print(f"{'─'*70}")

    def graceful_exit(sig, frame):
        print(f"\n{YELLOW}[*] Shutting down detector...{RESET}")
        save_report()
        sys.exit(0)

    signal.signal(signal.SIGINT,  graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    # Event loop
    while True:
        try:
            bpf.perf_buffer_poll(timeout=100)
        except Exception as e:
            print(f"{RED}[ERROR] {e}{RESET}")
            break


if __name__ == "__main__":
    main()
