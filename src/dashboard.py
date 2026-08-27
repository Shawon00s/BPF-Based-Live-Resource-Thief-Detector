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
DEVICE_NAME  = "n/a"
try:
    from live_predictor import LivePredictor
    predictor    = LivePredictor()
    ML_AVAILABLE = predictor.ready
    if ML_AVAILABLE:
        from live_predictor import DEVICE as _dev
        DEVICE_NAME = _dev.type          # "cuda" or "cpu", shown in the UI
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

# Paths under these prefixes are kernel interfaces, not user data. Daemons poll
# them thousands of times a second by design — nvidia-powerd reads
# /dev/cpu/N/msr for power management, systemd-oomd walks /sys/fs/cgroup — and
# counting those as "file opens" makes the exfiltration rule fire constantly.
# Reading them is not data theft, so they are excluded from the rate counter.
# They are still logged, and still checked against SENSITIVE_PATHS.
NOISE_PATH_PREFIXES = (
    "/proc/", "/sys/", "/dev/cpu/", "/dev/shm/", "/run/",
    "/dev/null", "/dev/urandom", "/dev/random", "/dev/pts/",
)
WHITELIST = {
    # shells & package tooling
    "systemd", "bash", "sh", "python3", "sshd", "cron",
    "apt", "dpkg", "snap", "snapd", "flask", "gunicorn",
    # editors / IDE threads
    "code", "code-tunnel", "electron", "node", "typescript",
    "ThreadPoolSingl", "ThreadPoolForeg", "ThreadPoolBack", "gmain", "pool-",
    # browsers — extremely chatty, and absent from 2011 training data.
    # Chromium spawns many named worker threads; comm is capped at 15 chars,
    # so these are the truncated forms the kernel actually reports.
    "chrome", "chromium", "firefox", "google-chrome-s", "google-chrome",
    "Chrome_ChildIOT", "Chrome_IOThread", "Compositor", "CompositorTileW",
    "GpuMemoryThread", "MemoryInfra", "NetworkService", "HangWatcher",
    "ThreadPoolServi", "VizCompositorTh", "Media", "AudioThread",
    # language servers / build tooling
    "cpptools", "cpptools-srv", "rust-analyzer", "gopls", "pylance",
    # desktop services
    "dbus-daemon", "NetworkManager", "gnome-shell", "Xorg", "Xwayland",
    "pipewire", "wireplumber", "gvfsd", "packagekitd", "upowerd", "colord",
    # hardware/telemetry daemons that poll kernel interfaces in tight loops
    "nvidia-powerd", "nvidia-persist", "irqbalance", "thermald", "systemd-oomd",
}

# ── Shared state ──────────────────────────────────────────────────────────────
event_queue   = queue.Queue(maxsize=500)    # BPF/demo thread → SSE /stream
recent_events = []                          # last 200 events for /api/events
pid_comms     = {}                          # pid → latest comm name (for ML alerts)
ml_last_alert = {}                          # pid → last ML alert timestamp
ml_anomalous  = set()                       # pids currently in the anomalous state

# ── ML auto-calibration ───────────────────────────────────────────────────────
# The LSTM was trained on ADFA-LD (Ubuntu 11.04, 2011). Modern desktop software
# — Chrome, VS Code, systemd — makes syscall sequences that look nothing like
# that era's "normal", so almost everything scores >0.9 and the log floods.
#
# Rather than hard-coding a threshold that suits one machine, spend the first
# CALIBRATION_SECONDS learning what THIS machine's normal looks like, then set
# the bar just above it. Alerts stay suppressed while calibrating.
ML_CALIBRATION_SECONDS = 90
ML_CALIBRATION_PCTL    = 99.5   # alert above this percentile of local normal
ml_cal_scores  = []             # scores observed during calibration
ml_cal_started = None           # set when the first syscall arrives
ml_cal_done    = False

# Once a full window scores anomalous, the next 100 syscalls will very likely
# score the same way — this cooldown stops one process flooding the log.
ML_ALERT_COOLDOWN = 60   # seconds before the same PID may alert again

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


# Perf-ring overflow accounting. The kernel drops events when user space
# cannot keep up; without tracking it, the only sign is "Possibly lost N
# samples" on the console and the UI silently shows an incomplete picture.
lost_samples = 0
_lost_last_report = 0.0

def handle_lost_samples(lost):
    """Called by BCC when the syscall perf ring overflows."""
    global lost_samples, _lost_last_report
    lost_samples += lost
    now = time.time()
    if now - _lost_last_report >= 30:      # summarise, never per-drop
        _lost_last_report = now
        push_event("WARN", 0, "system",
                   f"Perf ring overflow — {lost_samples:,} syscall samples dropped "
                   f"so far; ML sees a sampled subset")


def resolve_comm(pid: int) -> str:
    """
    Best-effort process name for a PID.

    pid_comms is only filled by file/proc events, so a process that never opens
    a file shows as "unknown" in ML alerts. Fall back to /proc/<pid>/comm, which
    the kernel keeps for every live process, and cache the result.
    """
    comm = pid_comms.get(pid)
    if comm:
        return comm
    try:
        with open(f"/proc/{pid}/comm") as f:
            comm = f.read().strip()
    except (OSError, ValueError):
        comm = "unknown"
    if comm and comm != "unknown":
        pid_comms[pid] = comm      # cache; PIDs are reused rarely enough
    return comm or "unknown"


# ── eBPF event handlers ───────────────────────────────────────────────────────

def handle_file_event(cpu, data, size):
    """Called by perf_buffer_poll for every openat() syscall."""
    global file_counts, last_reset

    event = bpf_instance["file_events"].event(data)
    pid   = event.pid
    comm  = event.comm.decode("utf-8", errors="replace").strip()
    fname = event.filename.decode("utf-8", errors="replace").strip()

    if not fname:
        return

    # Track comm name so ML thread can label its alerts
    pid_comms[pid] = comm

    # The whitelist exists to silence processes that are merely BUSY, so it is
    # applied to the rate rule only. Touching a sensitive path is a different
    # kind of signal and must never be suppressed: if anything at all reads
    # /etc/shadow we want to hear about it, whitelisted or not.
    if is_sensitive(fname):
        push_event("ALERT", pid, comm, "Sensitive file accessed", fname,
                   ml_score=get_ml_score(pid))
        return

    if comm in WHITELIST:
        return

    now = time.time()
    if now - last_reset >= WINDOW_SECONDS:
        file_counts.clear()
        last_reset = now
        alerted_pids.clear()

    # Only real filesystem reads count toward the exfiltration rate
    if not fname.startswith(NOISE_PATH_PREFIXES):
        file_counts[pid] += 1

    # Attach the latest LSTM score for this PID to every event (None until
    # the 100-syscall window fills; then shows real score even if normal)
    ml_score = get_ml_score(pid)

    if file_counts[pid] > FILE_RATE_THRESHOLD and pid not in alerted_pids:
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

    # The kernel captured comm at syscall time, so short-lived processes are
    # named correctly even though /proc/<pid> is already gone by now.
    if pid not in pid_comms:
        try:
            pid_comms[pid] = event.comm.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

    result = predictor.add_syscall(pid, syscall_nr)
    if result is None:
        return

    # ── Calibration phase: learn this machine's normal, do not alert ──────────
    global ml_cal_started, ml_cal_done
    if not ml_cal_done:
        now = time.time()
        if ml_cal_started is None:
            ml_cal_started = now
            push_event("INFO", 0, "system",
                       f"ML calibrating for {ML_CALIBRATION_SECONDS}s — "
                       f"learning this machine's normal syscall behaviour")
        ml_cal_scores.append(result["score"])

        if now - ml_cal_started >= ML_CALIBRATION_SECONDS and len(ml_cal_scores) >= 50:
            import statistics
            learned = statistics.quantiles(ml_cal_scores, n=1000)[int(ML_CALIBRATION_PCTL * 10) - 1]
            # Never drop below the notebook-derived floor. The ceiling is very
            # close to 1.0 because on a modern desktop most windows already
            # score ~0.99 — a 0.999 cap would leave the log still flooded.
            # Push a quarter of the remaining distance toward 1.0. The
            # predictor alerts on score >= threshold, so sitting exactly at the
            # observed percentile would still fire on ordinary traffic.
            learned = learned + (1.0 - learned) * 0.25
            new_thr = min(0.99999, max(predictor.ALERT_SCORE, round(learned, 6)))
            old_thr = predictor.ALERT_SCORE
            predictor.ALERT_SCORE = new_thr
            ml_cal_done = True
            push_event("INFO", 0, "system",
                       f"ML calibrated on {len(ml_cal_scores):,} windows — "
                       f"threshold {old_thr:.2f} -> {new_thr:.4f} "
                       f"(p{ML_CALIBRATION_PCTL} of local normal)")
        return   # no alerts while calibrating

    if not result["is_anomaly"]:
        # Score dropped back below threshold — arm the PID to alert again if it
        # later turns anomalous, so we report transitions rather than duration.
        ml_anomalous.discard(pid)
        return

    # ── This PID's latest full window scored above threshold ─────────────────

    comm = resolve_comm(pid)

    # Same whitelist the rule engine uses. Without this, systemd/chrome/VS Code
    # generate ML alerts constantly — they are busy, not malicious.
    if comm in WHITELIST:
        return

    # Report the TRANSITION into anomalous, not every window while it stays
    # that way. A process under sustained attack-like load would otherwise
    # re-alert every stride forever.
    if pid in ml_anomalous:
        return

    now = time.time()
    if now - ml_last_alert.get(pid, 0) < ML_ALERT_COOLDOWN:
        return

    ml_anomalous.add(pid)
    ml_last_alert[pid] = now

    push_event(
        "ALERT", pid, comm,
        f"🤖 LSTM anomaly — score {result['score']:.0%}",
        filename=f"ML full-window (score={result['score']:.4f}, threshold={predictor.ALERT_SCORE:.2f})",
        ml_score=result["score"],
    )


# ── Demo Mode ─────────────────────────────────────────────────────────────────

def _load_demo_attack_traces(limit=12):
    """
    Load real ADFA-LD attack traces and convert them to x86_64 numbering.

    Demo mode used to invent syscall patterns, but hand-made loops do not
    resemble the exploit sequences the LSTM was trained on, so it never fired
    and the ML panel looked broken. Replaying genuine attack traces makes the
    demo actually exercise the model.

    Returns [] if the dataset is absent — demo mode then falls back to
    synthetic bursts.
    """
    root = "/home/sudipto-roy-s-hawon/Downloads/ADFA-LD/Attack_Data_Master"
    if not (ML_AVAILABLE and predictor and os.path.isdir(root)):
        return []

    # predictor.syscall_map is x86_64 -> i686; invert it to go the other way
    inv = {}
    for x64, i686 in predictor.syscall_map.items():
        inv.setdefault(i686, x64)

    import glob as _glob
    traces = []
    for f in sorted(_glob.glob(os.path.join(root, "*", "*.txt")))[:limit]:
        try:
            nums = [int(x) for x in open(f).read().split() if x.isdigit()]
        except OSError:
            continue
        if len(nums) >= 100:
            traces.append([inv.get(n, n) for n in nums[:400]])   # -> x86_64
    if traces:
        print(f"[ML] Demo mode: loaded {len(traces)} real ADFA-LD attack traces")
    return traces


def _run_demo_mode(reason: str = "BCC not available or not root"):
    """
    Generate synthetic events indefinitely.
    The UI is fully functional in this mode; ML scoring still works.
    """
    import random, itertools

    # A PID keeps one name for its whole life, so bind comm to pid rather than
    # picking randomly each iteration — otherwise the ML panel shows an attack
    # trace running under the name "bash".
    DEMO_PROCS = {
        1000: "nginx",   1001: "curl",         1002: "python3",
        1003: "bash",    1004: "malware_sim",  1005: "data_stealer",
    }
    MALICIOUS = {"malware_sim", "data_stealer"}

    levels = ["INFO", "INFO", "INFO", "WARN", "ALERT"]
    files  = ["/etc/passwd", "/tmp/data.txt", "/home/user/doc.pdf",
              "/.ssh/id_rsa", "/var/log/syslog", "/etc/shadow"]

    _demo_attacks = _load_demo_attack_traces()

    push_event("INFO", 0, "system", f"DEMO mode — {reason}")

    for i in itertools.count(1):
        time.sleep(random.uniform(0.3, 1.2))
        fake_pid = 1000 + (i % len(DEMO_PROCS))
        comm     = DEMO_PROCS[fake_pid]
        fname    = random.choice(files)
        level    = ("ALERT" if comm in MALICIOUS and random.random() < 0.3
                    else random.choice(levels))
        push_event(level, fake_pid, comm,
                   "Sensitive file accessed" if level == "ALERT" else "File opened",
                   fname)

        # Feed syscalls into the LSTM synchronously — the same path the eBPF
        # handler uses, so demo mode exercises the real code.
        if ML_AVAILABLE and predictor:
            pid_comms[fake_pid] = comm

            if comm in MALICIOUS:
                # replay a real ADFA-LD attack trace so the LSTM actually fires
                if _demo_attacks:
                    tr = _demo_attacks[i % len(_demo_attacks)]
                    off = (i * 24) % max(1, len(tr) - 24)
                    burst = tr[off:off + 24]
                else:
                    burst = [257, 0, 257, 0, 257, 0, 44, 1] * 3
            else:
                # ordinary program: varied open/read/write/close/mmap
                burst = [257, 0, 1, 3, 9, 5, 21, 262,
                         random.randint(0, 300)] * 3

            for sc in burst:
                result = predictor.add_syscall(fake_pid, sc)
                if result and result["is_anomaly"]:
                    now = time.time()
                    if now - ml_last_alert.get(fake_pid, 0) >= ML_ALERT_COOLDOWN:
                        ml_last_alert[fake_pid] = now
                        push_event("ALERT", fake_pid, comm,
                                   f"🤖 LSTM anomaly — score {result['score']:.0%}",
                                   filename=f"ML full-window (demo, score={result['score']:.4f})",
                                   ml_score=result["score"])


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
        # file_events sees every openat() system-wide — on a busy desktop that
        # is tens of thousands per second. The BCC default is an 8-page ring
        # with a lost handler that prints "Possibly lost N samples" straight to
        # stderr, which is what floods the console. Give it a real buffer and
        # route drops through our own counter instead.
        bpf_instance["file_events"].open_perf_buffer(
            handle_file_event, page_cnt=256, lost_cb=handle_lost_samples)
        bpf_instance["proc_events"].open_perf_buffer(
            handle_proc_event, page_cnt=64, lost_cb=handle_lost_samples)
        bpf_instance["syscall_events"].open_perf_buffer(
            handle_syscall_event,
            page_cnt=512,             # 2 MB ring — syscalls are the busiest stream
            lost_cb=handle_lost_samples,
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



@app.route("/api/ml")
def api_ml():
    """
    Live view of what the LSTM is doing right now.

    The event-log badge only appears when a PID both reaches 50 syscalls AND
    opens a file, so on a quiet desktop the model looks idle even when it is
    working. This endpoint exposes the predictor's internal state directly:
    which PIDs are buffered, how full each window is, and their latest scores.
    """
    if not ML_AVAILABLE or predictor is None:
        return jsonify({"available": False})

    window   = predictor.WINDOW_SIZE
    min_disp = predictor.MIN_DISPLAY_SYSCALLS

    tracked = []
    # copy first — the BPF thread mutates these while we read
    for pid, buf in list(predictor.buffers.items()):
        n = len(buf)
        comm = pid_comms.get(pid, "?")
        tracked.append({
            "pid":     pid,
            "comm":    comm,
            "filled":  n,
            "percent": min(100, round(100 * n / window)),
            "score":   predictor.scores.get(pid),
            "scored":  n >= min_disp,
            "muted":   comm in WHITELIST,   # can never alert — shown, ranked last
        })

    # Whitelisted processes are suppressed from alerting, so showing them first
    # would fill the panel with rows that can never matter. Rank real candidates
    # above them, then by score, then by how full the window is.
    tracked.sort(key=lambda t: (t["muted"], -(t["score"] or 0), -t["filled"]))

    scored = [t for t in tracked if t["score"] is not None]
    return jsonify({
        "available":   True,
        "window":      window,
        "min_display": min_disp,
        "threshold":   predictor.ALERT_SCORE,
        "device":      str(DEVICE_NAME),
        "inferences":  predictor.inference_count,
        "calibrating": (not ml_cal_done) and BCC_AVAILABLE and os.geteuid() == 0,
        "cal_samples": len(ml_cal_scores),
        "lost":        lost_samples,
        "cal_left":    max(0, round(ML_CALIBRATION_SECONDS -
                                    (time.time() - ml_cal_started))) if ml_cal_started else ML_CALIBRATION_SECONDS,
        "tracked":     len(tracked),
        "ready":       sum(1 for t in tracked if t["filled"] >= window),
        "mean_score":  round(sum(t["score"] for t in scored) / len(scored), 4) if scored else None,
        "top":         tracked[:12],
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
