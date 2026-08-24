#!/usr/bin/env python3
"""
BPF-Based Live Resource Thief Detector — Multi-Threaded
OS Course Project

Threading Architecture (Producer-Consumer pattern):
  Thread 1  BPF Poller    — polls kernel perf buffer, feeds raw_queue
  Thread 2  Rule Engine   — rule-based detection, feeds alert_queue & ml_queue
  Thread 3  ML Engine     — LSTM anomaly inference, feeds alert_queue
  Thread 4  Alert Printer — consumes alert_queue, prints to terminal
  Thread 5  Report Writer — wakes every 60 s, auto-saves event log to disk

Inter-thread communication uses thread-safe queue.Queue objects.
Shared mutable state is protected with threading.Lock.
Graceful shutdown is coordinated via threading.Event.
"""

import os
import sys
import time
import signal
import datetime
import threading
import queue
from collections import defaultdict
from bcc import BPF

# ─── ANSI Color Codes ─────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ─── Detection Config ─────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/", "/.ssh/", "/root/",
    ".env", ".pem", ".key", "id_rsa",
    "credentials", "secret", "token", "password",
]
FILE_READ_THRESHOLD = 50          # files/sec per PID before ALERT
WINDOW_SECONDS      = 1
REPORT_INTERVAL     = 60          # auto-save report every 60 seconds
WHITELIST_PROCESSES = {
    "systemd", "bash", "python3", "sshd", "cron",
    "apt", "dpkg", "snap", "snapd", "code", "code-tunnel",
    "ThreadPoolSingl", "gmain", "electron", "node", "typescript",
}

# ─── Inter-thread Queues (Producer-Consumer) ──────────────────────────────────
# All queues are thread-safe by design (queue.Queue uses an internal lock)
raw_queue   = queue.Queue(maxsize=2000)  # Thread 1  → Thread 2
ml_queue    = queue.Queue(maxsize=500)   # Thread 2  → Thread 3
alert_queue = queue.Queue(maxsize=1000)  # Threads 2,3 → Thread 4

# ─── Shared State (protected by state_lock) ───────────────────────────────────
state_lock   = threading.Lock()
file_counts  = defaultdict(int)   # pid → file opens this window
last_reset   = time.time()
alerted_pids = set()
event_log    = []                 # accumulated for report

# ─── Shutdown Signal ──────────────────────────────────────────────────────────
# threading.Event: threads check this flag to know when to stop cleanly
shutdown_event = threading.Event()

# ─── BPF handle (set in main) ─────────────────────────────────────────────────
bpf = None


# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def is_sensitive(filename: str) -> bool:
    return any(p in filename for p in SENSITIVE_PATHS)


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║      BPF Resource Thief Detector — Multi-Threaded        ║
║      Kernel : {os.uname().release:<20}                  ║
║      Started: {datetime.datetime.now().strftime('%H:%M:%S %d-%b-%Y'):<20}             ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def save_report():
    """Write accumulated event_log to a timestamped report file."""
    path = (f"/home/sudipto-roy-s-hawon/Downloads/Project/reports/"
            f"report_{int(time.time())}.txt")
    with state_lock:
        snapshot = list(event_log)

    with open(path, "w") as f:
        f.write("BPF Resource Thief Detector — Session Report\n")
        f.write(f"Generated : {datetime.datetime.now()}\n")
        f.write(f"Events    : {len(snapshot)}\n")
        f.write("=" * 60 + "\n\n")
        for e in snapshot:
            f.write(
                f"[{e['level']}] {e['time']} | "
                f"PID {e['pid']} ({e['comm']}) | {e['detail']}\n"
            )
    print(f"\n{GREEN}[Report] Saved to {path}{RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# BPF CALLBACKS  (run inside Thread 1 — must be fast, no blocking)
# ══════════════════════════════════════════════════════════════════════════════

def handle_file_event(cpu, data, size):
    """
    BPF perf-buffer callback for openat events.
    Decodes the raw ctypes struct and drops it into raw_queue immediately.
    No detection logic here — keeps the callback as fast as possible so
    the kernel ring buffer never overflows.
    """
    event = bpf["file_events"].event(data)
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    if comm in WHITELIST_PROCESSES:
        return

    item = {
        "type":  "file",
        "pid":   event.pid,
        "uid":   event.uid,
        "comm":  comm,
        "fname": event.filename.decode("utf-8", errors="replace").strip(),
    }
    try:
        raw_queue.put_nowait(item)   # non-blocking; drop if full
    except queue.Full:
        pass                         # prefer dropping over blocking the kernel


def handle_proc_event(cpu, data, size):
    """
    BPF perf-buffer callback for execve events.
    Same fast-path approach: decode and enqueue, nothing else.
    """
    event = bpf["proc_events"].event(data)
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    if comm in WHITELIST_PROCESSES:
        return

    item = {
        "type":  "proc",
        "pid":   event.pid,
        "comm":  comm,
        "fname": event.filename.decode("utf-8", errors="replace").strip(),
    }
    try:
        raw_queue.put_nowait(item)
    except queue.Full:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# THREAD 1 — BPF Poller  (Producer)
# ══════════════════════════════════════════════════════════════════════════════

def bpf_poller_thread():
    """
    Thread 1: BPF Poller

    Continuously calls bpf.perf_buffer_poll(), which triggers the BPF
    callbacks above whenever a new kernel event arrives.

    Role    : Producer — puts raw event dicts into raw_queue
    Blocks  : on perf_buffer_poll (timeout=100 ms)
    Stops   : when shutdown_event is set
    """
    while not shutdown_event.is_set():
        try:
            bpf.perf_buffer_poll(timeout=100)
        except Exception as e:
            if not shutdown_event.is_set():
                print(f"{RED}[BPF Poller] Error: {e}{RESET}")
            break


# ══════════════════════════════════════════════════════════════════════════════
# THREAD 2 — Rule Engine  (Consumer → Producer)
# ══════════════════════════════════════════════════════════════════════════════

def rule_engine_thread():
    """
    Thread 2: Rule Engine

    Consumes raw_queue events and applies two rule-based detection strategies:
      - Sensitive path detection  (pattern match)
      - High-frequency rate detection  (threshold in a time window)

    Puts detection alerts into alert_queue.
    Also forwards every file event to ml_queue for LSTM scoring (Thread 3).

    Shared state (file_counts, last_reset, alerted_pids) is protected
    by state_lock to prevent race conditions with other threads.

    Role    : Consumer of raw_queue, Producer for alert_queue & ml_queue
    Blocks  : on raw_queue.get() with a short timeout
    Stops   : when shutdown_event is set and queue is drained
    """
    global last_reset

    suspicious_execs = [
        "ncat", "nc", "netcat", "curl", "wget",
        "socat", "reverse", "exploit", "msfconsole",
    ]

    while not shutdown_event.is_set() or not raw_queue.empty():
        try:
            item = raw_queue.get(timeout=0.2)
        except queue.Empty:
            continue

        pid   = item["pid"]
        comm  = item["comm"]
        fname = item.get("fname", "")

        # ── File event rules ──────────────────────────────────────────────────
        if item["type"] == "file":
            with state_lock:
                # Reset rate window
                now = time.time()
                if now - last_reset >= WINDOW_SECONDS:
                    file_counts.clear()
                    alerted_pids.clear()
                    last_reset = now

                file_counts[pid] += 1
                count_this_window = file_counts[pid]
                already_alerted   = pid in alerted_pids

            # Rule 1: Sensitive file access
            if is_sensitive(fname):
                alert_queue.put({
                    "level":  "ALERT",
                    "pid":    pid,
                    "comm":   comm,
                    "detail": f"Sensitive file accessed -> {fname}",
                    "source": "rule",
                })

            # Rule 2: High-frequency access (exfiltration pattern)
            elif count_this_window > FILE_READ_THRESHOLD and not already_alerted:
                with state_lock:
                    alerted_pids.add(pid)
                alert_queue.put({
                    "level":  "ALERT",
                    "pid":    pid,
                    "comm":   comm,
                    "detail": (f"High-speed file access: "
                               f"{count_this_window}/sec — possible exfiltration"),
                    "source": "rule",
                })

            # Forward to ML engine for LSTM scoring
            try:
                ml_queue.put_nowait(item)
            except queue.Full:
                pass

        # ── Process event rules ───────────────────────────────────────────────
        elif item["type"] == "proc":
            level = ("WARN"
                     if any(k in fname.lower() for k in suspicious_execs)
                     else "INFO")
            alert_queue.put({
                "level":  level,
                "pid":    pid,
                "comm":   comm,
                "detail": f"New process spawned -> {fname}",
                "source": "rule",
            })

        raw_queue.task_done()


# ══════════════════════════════════════════════════════════════════════════════
# THREAD 3 — ML Engine  (Consumer → Producer)
# ══════════════════════════════════════════════════════════════════════════════

def ml_engine_thread():
    """
    Thread 3: ML Engine

    Consumes ml_queue file events.
    Feeds syscall numbers into the LivePredictor's sliding window.
    When the window fills (every 100 syscalls), the LSTM runs on the GPU
    and produces an anomaly probability score.
    If score >= threshold (0.5), an ALERT is pushed to alert_queue.

    Running inference in its own thread means the rule engine (Thread 2)
    is never blocked waiting for GPU computation.

    Role    : Consumer of ml_queue, Producer for alert_queue
    Blocks  : on ml_queue.get() with timeout
    Stops   : when shutdown_event is set and queue is drained
    """
    # Lazy-load the predictor so startup is not delayed if the model is missing
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from ml.live_predictor import LivePredictor
        predictor = LivePredictor()
        ml_ready  = predictor.ready
    except Exception as e:
        print(f"{YELLOW}[ML Engine] Could not load predictor: {e}{RESET}")
        ml_ready = False

    if not ml_ready:
        print(f"{YELLOW}[ML Engine] Running without ML scoring.{RESET}")
        # Drain ml_queue silently so it does not fill up
        while not shutdown_event.is_set():
            try:
                ml_queue.get(timeout=0.2)
                ml_queue.task_done()
            except queue.Empty:
                continue
        return

    # Map event type to a representative syscall number for the LSTM
    # openat = 257, execve = 59  (x86_64 Linux syscall numbers)
    TYPE_TO_SYSCALL = {"file": 257, "proc": 59}

    while not shutdown_event.is_set() or not ml_queue.empty():
        try:
            item = ml_queue.get(timeout=0.2)
        except queue.Empty:
            continue

        pid        = item["pid"]
        syscall_nr = TYPE_TO_SYSCALL.get(item["type"], 0)
        result     = predictor.add_syscall(pid, syscall_nr)

        # result is None until the 100-syscall window is full
        if result and result["is_anomaly"]:
            alert_queue.put({
                "level":  "ALERT",
                "pid":    pid,
                "comm":   item["comm"],
                "detail": (f"[ML] LSTM anomaly score: {result['score']:.3f} "
                           f"(threshold 0.50) — behaviour classified as ATTACK"),
                "source": "ml",
            })

        ml_queue.task_done()


# ══════════════════════════════════════════════════════════════════════════════
# THREAD 4 — Alert Printer  (Consumer)
# ══════════════════════════════════════════════════════════════════════════════

def alert_printer_thread():
    """
    Thread 4: Alert Printer

    The single thread that is allowed to write to stdout.
    Keeping all output in one thread eliminates interleaved / garbled lines
    that would happen if multiple threads printed simultaneously.

    Also appends every alert to event_log (protected by state_lock)
    so the Report Writer (Thread 5) can flush it to disk periodically.

    Role    : Consumer of alert_queue
    Blocks  : on alert_queue.get() with timeout
    Stops   : when shutdown_event is set and queue is drained
    """
    level_color = {"ALERT": RED, "WARN": YELLOW, "INFO": CYAN}

    while not shutdown_event.is_set() or not alert_queue.empty():
        try:
            ev = alert_queue.get(timeout=0.2)
        except queue.Empty:
            continue

        ts    = datetime.datetime.now().strftime("%H:%M:%S")
        level = ev["level"]
        color = level_color.get(level, RESET)
        src   = f"[{ev.get('source','?').upper()}]"

        print(
            f"{color}[{level}]{RESET} {ts} {src} "
            f"PID {BOLD}{ev['pid']:<6}{RESET} "
            f"({ev['comm']:<20}) | {ev['detail']}"
        )

        # Log for report
        with state_lock:
            event_log.append({
                "time":   ts,
                "level":  level,
                "pid":    ev["pid"],
                "comm":   ev["comm"],
                "detail": ev["detail"],
            })

        alert_queue.task_done()


# ══════════════════════════════════════════════════════════════════════════════
# THREAD 5 — Report Writer  (Timer thread)
# ══════════════════════════════════════════════════════════════════════════════

def report_writer_thread():
    """
    Thread 5: Report Writer

    Wakes up every REPORT_INTERVAL seconds and saves the current event_log
    to disk without blocking any other thread.

    Uses shutdown_event.wait(timeout) instead of time.sleep() so it can
    react to a shutdown signal immediately rather than after the full interval.

    Role    : Timer — wakes periodically, writes file, sleeps again
    Stops   : when shutdown_event is set
    """
    while not shutdown_event.wait(timeout=REPORT_INTERVAL):
        with state_lock:
            count = len(event_log)
        if count > 0:
            save_report()

    # Final save on shutdown
    save_report()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if os.geteuid() != 0:
        print(f"{RED}[ERROR] Must run as root: sudo python3 detector.py{RESET}")
        sys.exit(1)

    banner()

    # ── Load and compile eBPF sensor ──────────────────────────────────────────
    sensor_path = os.path.join(os.path.dirname(__file__), "ebpf_sensor.c")
    with open(sensor_path) as f:
        bpf_src = f.read()

    global bpf
    print(f"{CYAN}[*] Compiling and attaching eBPF probes...{RESET}")
    bpf = BPF(text=bpf_src)
    bpf["file_events"].open_perf_buffer(handle_file_event, page_cnt=64)
    bpf["proc_events"].open_perf_buffer(handle_proc_event, page_cnt=16)
    print(f"{GREEN}[+] eBPF probes attached successfully!{RESET}\n")

    # ── Launch all threads ────────────────────────────────────────────────────
    threads = [
        threading.Thread(target=bpf_poller_thread,   name="BPF-Poller",    daemon=True),
        threading.Thread(target=rule_engine_thread,   name="Rule-Engine",   daemon=True),
        threading.Thread(target=ml_engine_thread,     name="ML-Engine",     daemon=True),
        threading.Thread(target=alert_printer_thread, name="Alert-Printer", daemon=True),
        threading.Thread(target=report_writer_thread, name="Report-Writer", daemon=True),
    ]

    for t in threads:
        t.start()

    # Print thread table
    print(f"{'─'*60}")
    print(f"  {'Thread':<20} {'Name':<20} Status")
    print(f"{'─'*60}")
    for t in threads:
        print(f"  TID {t.ident:<16} {t.name:<20} {'alive' if t.is_alive() else 'dead'}")
    print(f"{'─'*60}\n")

    print(f"{'Level':<8} {'Time':<10} {'Src':<6} {'PID':<8} {'Process':<22} {'Detail'}")
    print(f"{'─'*70}")

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    def graceful_exit(sig, frame):
        print(f"\n{YELLOW}[*] Shutdown signal received. Stopping threads...{RESET}")
        shutdown_event.set()     # signal all threads to stop

        # Wait for queues to drain (max 5 seconds)
        for q in (raw_queue, ml_queue, alert_queue):
            try:
                q.join()
            except Exception:
                pass

        print(f"{GREEN}[*] All threads stopped cleanly.{RESET}")
        sys.exit(0)

    signal.signal(signal.SIGINT,  graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    # ── Main thread: monitor thread health ────────────────────────────────────
    # The main thread stays alive and watches for dead threads.
    # All real work happens in the five daemon threads above.
    while not shutdown_event.is_set():
        time.sleep(5)
        dead = [t.name for t in threads if not t.is_alive()]
        if dead:
            print(f"{RED}[WARN] Thread(s) died unexpectedly: {dead}{RESET}")


if __name__ == "__main__":
    main()
