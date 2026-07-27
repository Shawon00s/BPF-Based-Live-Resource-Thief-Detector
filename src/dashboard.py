#!/usr/bin/env python3
"""
BPF Resource Thief Detector — Web Dashboard
Runs BPF monitoring in a background thread and streams events
to the browser via Server-Sent Events (SSE).

Run: sudo python3 dashboard.py
Then open: http://localhost:5000
"""

import os
import sys
import time
import json
import queue
import threading
import datetime
from collections import defaultdict

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    from flask import Flask, Response, render_template, jsonify
except ImportError:
    sys.exit("Flask not found. Run: pip3 install flask --user")

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
    "/.ssh/", "/root/", ".env", ".pem", ".key", "id_rsa",
    "credentials", "secret", "token", "password",
]
FILE_RATE_THRESHOLD = 50      # files/second per PID
WINDOW_SECONDS      = 1
WHITELIST = {
    "systemd", "bash", "python3", "sshd", "cron",
    "apt", "dpkg", "snap", "snapd", "code", "code-tunnel",
    "flask", "gunicorn",
    "ThreadPoolSingl", "gmain", "pool-",              # VS Code / IDE threads
    "electron", "node", "typescript",
}

# ── Shared state ──────────────────────────────────────────────────────────────
event_queue   = queue.Queue(maxsize=500)   # BPF thread → SSE stream
recent_events = []                         # last 200 events for /api/events
stats = {
    "total": 0, "alerts": 0, "warns": 0,
    "top_procs": defaultdict(int),         # comm → event count
    "timeline": [],                        # [{ts, alerts, warns, infos}, ...]
}
stats_lock = threading.Lock()

file_counts  = defaultdict(int)
last_reset   = time.time()
alerted_pids = set()

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_sensitive(path: str) -> bool:
    return any(p in path for p in SENSITIVE_PATHS)


def push_event(level: str, pid: int, comm: str, detail: str, filename: str = ""):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    ev = {
        "ts": ts, "level": level,
        "pid": pid, "comm": comm,
        "detail": detail, "filename": filename,
    }
    with stats_lock:
        stats["total"] += 1
        if level == "ALERT": stats["alerts"] += 1
        elif level == "WARN": stats["warns"] += 1
        stats["top_procs"][comm] += 1
        recent_events.append(ev)
        if len(recent_events) > 200:
            recent_events.pop(0)

    try:
        event_queue.put_nowait(ev)
    except queue.Full:
        event_queue.get_nowait()   # drop oldest
        event_queue.put_nowait(ev)


# ── BPF event handlers ────────────────────────────────────────────────────────

def handle_file_event(cpu, data, size):
    global file_counts, last_reset

    event = bpf_instance["file_events"].event(data)
    pid   = event.pid
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    fname = event.filename.decode("utf-8", errors="replace").strip()

    if comm in WHITELIST or not fname:
        return

    now = time.time()
    if now - last_reset >= WINDOW_SECONDS:
        file_counts.clear()
        last_reset = now
        alerted_pids.clear()

    file_counts[pid] += 1

    if is_sensitive(fname):
        push_event("ALERT", pid, comm,
                   f"Sensitive file accessed", fname)
    elif file_counts[pid] > FILE_RATE_THRESHOLD and pid not in alerted_pids:
        alerted_pids.add(pid)
        push_event("ALERT", pid, comm,
                   f"High-speed file access: {file_counts[pid]}/sec — possible exfiltration", fname)
    else:
        push_event("INFO", pid, comm, f"File opened", fname)


def handle_proc_event(cpu, data, size):
    event = bpf_instance["proc_events"].event(data)
    pid   = event.pid
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    fname = event.filename.decode("utf-8", errors="replace").strip()

    if comm in WHITELIST:
        return

    suspicious = ["ncat", "nc", "netcat", "curl", "wget",
                  "socat", "reverse", "exploit", "msfconsole"]
    level = "WARN" if any(k in fname.lower() for k in suspicious) else "INFO"
    push_event(level, pid, comm, f"New process spawned", fname)


# ── BPF monitoring thread ─────────────────────────────────────────────────────
bpf_instance = None
bpf_running  = False

def bpf_thread():
    global bpf_instance, bpf_running

    if not BCC_AVAILABLE:
        # Demo mode: generate fake events so the UI is testable without root
        import random, itertools
        procs  = ["nginx", "curl", "python3", "bash", "malware_sim", "data_stealer"]
        levels = ["INFO", "INFO", "INFO", "WARN", "ALERT"]
        files  = ["/etc/passwd", "/tmp/data.txt", "/home/user/doc.pdf",
                  "/.ssh/id_rsa", "/var/log/syslog", "/etc/shadow"]
        push_event("INFO", 0, "system", "Running in DEMO mode — BCC not available or not root")
        for i in itertools.count(1):
            time.sleep(random.uniform(0.3, 1.2))
            level = random.choice(levels)
            comm  = random.choice(procs)
            fname = random.choice(files)
            push_event(level, 1000 + i % 50, comm,
                       "Sensitive file accessed" if level == "ALERT" else "File opened",
                       fname)
        return

    sensor_path = os.path.join(os.path.dirname(__file__), "ebpf_sensor.c")
    with open(sensor_path) as f:
        src = f.read()

    bpf_instance = BPF(text=src)
    bpf_instance["file_events"].open_perf_buffer(handle_file_event)
    bpf_instance["proc_events"].open_perf_buffer(handle_proc_event)

    push_event("INFO", 0, "system", "eBPF probes attached — monitoring started")
    bpf_running = True

    while True:
        try:
            bpf_instance.perf_buffer_poll(timeout=100)
        except Exception as e:
            push_event("WARN", 0, "system", f"BPF poll error: {e}")
            break


# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/stream")
def stream():
    """Server-Sent Events endpoint — browser connects here for live data."""
    def event_generator():
        yield f"data: {json.dumps({'type':'connected','msg':'Stream connected'})}\n\n"
        while True:
            try:
                ev = event_queue.get(timeout=15)
                yield f"data: {json.dumps(ev)}\n\n"
            except queue.Empty:
                yield ": heartbeat\n\n"   # keep connection alive

    return Response(event_generator(),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/events")
def api_events():
    with stats_lock:
        return jsonify(list(recent_events[-50:]))


@app.route("/api/stats")
def api_stats():
    with stats_lock:
        top = sorted(stats["top_procs"].items(), key=lambda x: x[1], reverse=True)[:8]
        return jsonify({
            "total":  stats["total"],
            "alerts": stats["alerts"],
            "warns":  stats["warns"],
            "top_procs": top,
            "bcc_available": BCC_AVAILABLE,
            "is_root": os.geteuid() == 0,
        })


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if BCC_AVAILABLE and os.geteuid() != 0:
        print("[WARN] Not running as root — starting in DEMO mode (fake events).")
        print("[WARN] For real monitoring: sudo python3 dashboard.py\n")

    t = threading.Thread(target=bpf_thread, daemon=True)
    t.start()

    print("\n╔══════════════════════════════════════════════╗")
    print("║   BPF Resource Thief Detector — Dashboard   ║")
    print("║   Open browser: http://localhost:5000        ║")
    print("╚══════════════════════════════════════════════╝\n")

    app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)