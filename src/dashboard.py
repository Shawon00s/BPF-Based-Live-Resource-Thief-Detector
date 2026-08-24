#!/usr/bin/env python3
"""
BPF Resource Thief Detector — Web Dashboard
============================================
Runs BPF monitoring in a background thread and streams events to the browser
via Server-Sent Events (SSE).

Detection pipeline:
  eBPF sensor  →  rule engine  (sensitive paths, file-rate threshold)
               →  LSTM engine  (LivePredictor sliding-window anomaly score)

Run:  sudo python3 dashboard.py
Open: http://localhost:5000
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
    sys.exit("Flask not found.  Run: pip3 install flask")

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False

# ── ML: load LivePredictor (LSTM) ─────────────────────────────────────────────
_ml_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ml')
if _ml_dir not in sys.path:
    sys.path.insert(0, _ml_dir)

ML_AVAILABLE = False
predictor    = None
try:
    from live_predictor import LivePredictor
    predictor    = LivePredictor()
    ML_AVAILABLE = predictor.ready
    if ML_AVAILABLE:
        print("[ML] LSTM model loaded — real-time anomaly scoring enabled ✓")
    else:
        print("[ML] Model files not found. Run: python3 ml/lstm_train.py")

except ImportError as _ml_err:
    # Most common cause: launched with sudo, which resets $HOME to /root, so
    # Python can no longer see packages installed with `pip install --user`.
    print(f"[ML] DISABLED — missing module: {_ml_err.name}")
    if os.geteuid() == 0 and not os.environ.get("PYTHONPATH"):
        print("[ML] Cause: running as root without PYTHONPATH — packages in")
        print("[ML]        ~/.local are invisible because $HOME is now /root.")
        print("[ML] Fix  : start with 'bash run.sh' (it sets PYTHONPATH),")
        print(f"[ML]        or: pip install {_ml_err.name} into the venv itself.")
    else:
        print(f"[ML] Fix  : {sys.executable} -m pip install {_ml_err.name}")

except Exception as _ml_err:
    print(f"[ML] DISABLED — could not load LivePredictor: {_ml_err}")

# ── Config ────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
    "/.ssh/", "/root/", ".env", ".pem", ".key", "id_rsa",
    "credentials", "secret", "token", "password",
]
FILE_RATE_THRESHOLD = 50      # file opens / second per PID → alert
WINDOW_SECONDS      = 1
WHITELIST = {
    "systemd", "bash", "python3", "sshd", "cron",
    "apt", "dpkg", "snap", "snapd", "code", "code-tunnel",
    "flask", "gunicorn",
    "ThreadPoolSingl", "gmain", "pool-",   # VS Code / IDE threads
    "electron", "node", "typescript",
}

# ── Shared state ──────────────────────────────────────────────────────────────
event_queue   = queue.Queue(maxsize=500)    # BPF/demo thread → SSE /stream
recent_events = []                          # last 200 events for /api/events
pid_comms     = {}                          # pid → latest comm name (for ML alerts)
ml_last_alert = {}                          # pid → last ML alert timestamp

# Once a full window scores anomalous, the next 100 syscalls will very likely
# score the same way — this cooldown stops one process flooding the log.
ML_ALERT_COOLDOWN = 10   # seconds between ML alerts for the same PID

stats = {
    "total":         0,
    "alerts":        0,
    "warns":         0,
    "ml_detections": 0,          # LSTM-triggered alerts
    "top_procs":     defaultdict(int),
}
stats_lock = threading.Lock()

file_counts  = defaultdict(int)
last_reset   = time.time()
alerted_pids = set()

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_sensitive(path: str) -> bool:
    return any(p in path for p in SENSITIVE_PATHS)


def push_event(level: str, pid: int, comm: str, detail: str,
               filename: str = "", ml_score: float = None):
    """Append one event to shared state and enqueue it for SSE streaming."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    ev = {
        "ts":       ts,
        "level":    level,
        "pid":      pid,
        "comm":     comm,
        "detail":   detail,
        "filename": filename,
    }
    if ml_score is not None:
        ev["ml_score"] = round(ml_score, 4)   # send score to frontend

    with stats_lock:
        stats["total"] += 1
        if level == "ALERT":
            stats["alerts"] += 1
            if ml_score is not None:
                stats["ml_detections"] += 1
        elif level == "WARN":
            stats["warns"] += 1
        stats["top_procs"][comm] += 1
        recent_events.append(ev)
        if len(recent_events) > 200:
            recent_events.pop(0)

    try:
        event_queue.put_nowait(ev)
    except queue.Full:
        event_queue.get_nowait()   # drop oldest to make room
        event_queue.put_nowait(ev)


# ── ML Score Helper ───────────────────────────────────────────────────────────

def get_ml_score(pid: int):
    """
    Return the latest LSTM anomaly score for a PID, for DISPLAY in the UI.

    Order of preference:
      1. Cached score from a completed 100-syscall window (most reliable)
      2. Partial score once ≥50 syscalls are buffered (lower confidence)
      3. None — not enough syscalls seen yet, UI shows "—"

    Note this is only the badge in the event log.  Actual ML alerts are
    raised in handle_syscall_event() and require a full window.
    """
    if not ML_AVAILABLE or predictor is None:
        return None
    score = predictor.get_score(pid)          # cached from last full window
    if score is None:
        result = predictor.partial_score(pid)  # needs MIN_DISPLAY_SYSCALLS
        if result:
            score = result["score"]
    return score


# ── eBPF event handlers ───────────────────────────────────────────────────────

def handle_file_event(cpu, data, size):
    """Called by perf_buffer_poll for every openat() syscall."""
    global file_counts, last_reset

    event = bpf_instance["file_events"].event(data)
    pid   = event.pid
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    fname = event.filename.decode("utf-8", errors="replace").strip()

    if comm in WHITELIST or not fname:
        return

    # Track comm name so ML thread can label its alerts
    pid_comms[pid] = comm

    now = time.time()
    if now - last_reset >= WINDOW_SECONDS:
        file_counts.clear()
        last_reset = now
        alerted_pids.clear()

    file_counts[pid] += 1

    # Attach the latest LSTM score for this PID to every event (None until
    # the 100-syscall window fills; then shows real score even if normal)
    ml_score = get_ml_score(pid)

    if is_sensitive(fname):
        push_event("ALERT", pid, comm, "Sensitive file accessed", fname,
                   ml_score=ml_score)
    elif file_counts[pid] > FILE_RATE_THRESHOLD and pid not in alerted_pids:
        alerted_pids.add(pid)
        push_event("ALERT", pid, comm,
                   f"High-speed file access: {file_counts[pid]}/sec — possible exfiltration",
                   fname, ml_score=ml_score)
    else:
        push_event("INFO", pid, comm, "File opened", fname, ml_score=ml_score)


def handle_proc_event(cpu, data, size):
    """Called by perf_buffer_poll for every execve() syscall."""
    event = bpf_instance["proc_events"].event(data)
    pid   = event.pid
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    fname = event.filename.decode("utf-8", errors="replace").strip()

    if comm in WHITELIST:
        return

    pid_comms[pid] = comm

    ml_score = get_ml_score(pid)

    suspicious = ["ncat", "nc", "netcat", "curl", "wget",
                  "socat", "reverse", "exploit", "msfconsole"]
    level = "WARN" if any(k in fname.lower() for k in suspicious) else "INFO"
    push_event(level, pid, comm, "New process spawned", fname, ml_score=ml_score)


def handle_syscall_event(cpu, data, size):
    """
    Feed each syscall DIRECTLY into LivePredictor — synchronous, no queue.

    Why synchronous?  handle_file_event() checks predictor.buffers[pid] to
    show an ML score badge.  If we used an async queue, the file event would
    be pushed to the browser BEFORE the ML thread processed the syscall,
    so the badge would always be empty.  Calling add_syscall() here ensures
    the buffer is populated before the next file event fires for the same PID.

    LSTM inference only runs every 100 syscalls (or at the 15-syscall partial
    checkpoint), so the per-call overhead is just a deque.append() — fast.
    """
    if not ML_AVAILABLE or predictor is None:
        return

    event      = bpf_instance["syscall_events"].event(data)
    pid        = event.pid
    syscall_nr = event.syscall_nr

    result = predictor.add_syscall(pid, syscall_nr)

    # Alert ONLY on a full 100-syscall window.
    # Partial windows are display-only — they are ~78% false positives at 15
    # syscalls because heavy PAD_TOKEN padding reads as anomalous to the model.
    if result and result["is_anomaly"]:
        # Rate-limit: one ML alert per PID per ML_ALERT_COOLDOWN seconds
        now = time.time()
        if now - ml_last_alert.get(pid, 0) < ML_ALERT_COOLDOWN:
            return
        ml_last_alert[pid] = now

        comm = pid_comms.get(pid, "unknown")
        push_event(
            "ALERT", pid, comm,
            f"🤖 LSTM anomaly — score {result['score']:.0%}",
            filename=f"ML full-window (score={result['score']:.4f}, threshold={predictor.ALERT_SCORE:.2f})",
            ml_score=result["score"],
        )


# ── Demo Mode ─────────────────────────────────────────────────────────────────

def _run_demo_mode(reason: str = "BCC not available or not root"):
    """
    Generate synthetic events indefinitely.
    The UI is fully functional in this mode; ML scoring still works.
    """
    import random, itertools
    procs  = ["nginx", "curl", "python3", "bash", "malware_sim", "data_stealer"]
    levels = ["INFO", "INFO", "INFO", "WARN", "ALERT"]
    files  = ["/etc/passwd", "/tmp/data.txt", "/home/user/doc.pdf",
              "/.ssh/id_rsa", "/var/log/syslog", "/etc/shadow"]

    push_event("INFO", 0, "system", f"DEMO mode — {reason}")

    for i in itertools.count(1):
        time.sleep(random.uniform(0.3, 1.2))
        level = random.choice(levels)
        comm  = random.choice(procs)
        fname = random.choice(files)
        push_event(level, 1000 + i % 50, comm,
                   "Sensitive file accessed" if level == "ALERT" else "File opened",
                   fname)

        # Feed synthetic syscall numbers directly into LSTM (synchronous)
        if ML_AVAILABLE and predictor:
            fake_pid = 1000 + i % 50
            pid_comms[fake_pid] = comm
            for sc in [257, 1, 3, 5, random.randint(0, 300)]:
                predictor.add_syscall(fake_pid, sc)


# ── BPF Monitoring Thread ─────────────────────────────────────────────────────
bpf_instance = None
bpf_running  = False

def bpf_thread():
    global bpf_instance, bpf_running

    if not BCC_AVAILABLE:
        _run_demo_mode()
        return

    sensor_path = os.path.join(os.path.dirname(__file__), "ebpf_sensor.c")
    with open(sensor_path) as f:
        src = f.read()

    # Tell the sensor our own PID so it can skip our syscalls.
    # Without this, reading the perf buffer generates syscalls that get traced,
    # which produce more events to read — a feedback loop that floods the ring.
    src = f"#define SELF_PID {os.getpid()}\n" + src

    try:
        bpf_instance = BPF(text=src)
    except Exception as compile_err:
        short = str(compile_err).splitlines()[0][:120]
        push_event("WARN", 0, "system", f"eBPF compile error: {short}")
        _run_demo_mode(reason=f"eBPF compile failed: {short}")
        return

    try:
        bpf_instance["file_events"].open_perf_buffer(handle_file_event)
        bpf_instance["proc_events"].open_perf_buffer(handle_proc_event)
        bpf_instance["syscall_events"].open_perf_buffer(
            handle_syscall_event, page_cnt=256   # larger ring for high-volume syscall stream
        )
    except Exception as attach_err:
        short = str(attach_err).splitlines()[0][:120]
        push_event("WARN", 0, "system", f"eBPF attach error: {short}")
        _run_demo_mode(reason=f"eBPF attach failed: {short}")
        return

    push_event("INFO", 0, "system",
               f"eBPF probes attached — monitoring started"
               + (" | LSTM scoring active ✓" if ML_AVAILABLE else ""))
    bpf_running = True

    while True:
        try:
            bpf_instance.perf_buffer_poll(timeout=100)
        except Exception as e:
            push_event("WARN", 0, "system", f"BPF poll error: {e}")
            break


# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/stream")
def stream():
    """Server-Sent Events — browser connects here for live data."""
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
            "total":         stats["total"],
            "alerts":        stats["alerts"],
            "warns":         stats["warns"],
            "ml_detections": stats["ml_detections"],
            "top_procs":     top,
            "bcc_available": BCC_AVAILABLE,
            "ml_available":  ML_AVAILABLE,
            "is_root":       os.geteuid() == 0,
        })


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if BCC_AVAILABLE and os.geteuid() != 0:
        print("[WARN] Not root — starting in DEMO mode (fake events).")
        print("[WARN] For real monitoring run:  sudo bash run.sh\n")

    # Start BPF monitoring thread (ML runs synchronously inside it — no separate thread)
    bpf_t = threading.Thread(target=bpf_thread, name="BPF-Monitor", daemon=True)
    bpf_t.start()

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║     BPF Resource Thief Detector — Dashboard          ║")
    print("║     Open browser:  http://localhost:5000             ║")
    ml_status = "LSTM model active ✓" if ML_AVAILABLE else "ML model not loaded"
    print(f"║     ML status  :  {ml_status:<34}║")
    print("╚══════════════════════════════════════════════════════╝\n")

    app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)
