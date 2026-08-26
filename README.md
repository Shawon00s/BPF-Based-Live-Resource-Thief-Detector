# BPF-Based Live Resource Thief Detector

OS Course Project · Ubuntu 26.04 · Kernel 7.0 · RTX 3050 6 GB

Detects processes that steal system resources — reading sensitive files,
sweeping the filesystem, spawning suspicious children — by tracing **every
syscall in the kernel with eBPF** and scoring behaviour with a trained LSTM.

Two independent detection layers:

| Layer | Catches | Cost |
|---|---|---|
| **Rules** | known-bad paths (`/etc/shadow`), file-open rate > 50/s | ~0 |
| **LSTM** | unusual *sequences* of ordinary syscalls | ~1 ms / 100 syscalls, GPU |

Rules catch what you already thought of. The model catches what you did not.

## Layout

```
Project/
├── src/
│   ├── ebpf_sensor.c        kernel-space probe — RAW_TRACEPOINT on sys_enter
│   ├── dashboard.py         Flask + SSE web dashboard  (main entry point)
│   ├── detector.py          terminal-only detector, 5-thread pipeline
│   ├── simulate_thief.py    attack simulator for testing
│   └── templates/index.html live UI — charts, event log, ML score badges
├── ml/
│   ├── 01_explore_dataset.ipynb    dataset + syscall ABI discovery
│   ├── 02_isolation_forest.ipynb   unsupervised baseline
│   ├── 03_lstm_train.ipynb         GPU sequence model
│   ├── 04_live_inference.ipynb     validation + threshold tuning
│   ├── live_predictor.py           live scorer imported by dashboard.py
│   ├── syscall_map.json            376 x86-64 -> i686 translations
│   └── saved_model/                trained weights
└── run.sh                   launcher (handles sudo + PYTHONPATH)
```

## Running it

```bash
cd ~/Downloads/Project
bash run.sh                      # needs root for eBPF
```

Open **http://localhost:5000**. Expected on startup:

```
[ML] LSTM loaded on cuda | AUC=0.9854
[ML] Syscall ABI map loaded: 376 x86_64 -> i686 translations
[ML] LSTM model loaded — real-time anomaly scoring enabled
```

Without root it starts in **demo mode**, which replays real ADFA-LD attack
traces through the same code path — useful for seeing the model fire without
needing a live attack:

```bash
venv/bin/python3 src/dashboard.py       # no sudo — demo mode
```

Generate suspicious activity in a second terminal:

```bash
venv/bin/python3 src/simulate_thief.py snoop    # sensitive-file access
venv/bin/python3 src/simulate_thief.py rapid    # high-rate file sweep
```

Terminal-only version, no web UI:

```bash
sudo venv/bin/python3 src/detector.py
```

## How it works

```
  kernel                          user space
  ──────                          ──────────
  every syscall
      │
  RAW_TRACEPOINT_PROBE(sys_enter)
      │
      ├── syscall_events ──► LivePredictor ──► LSTM ──► score 0.0–1.0
      │                      (100-syscall              │
      │                       window per PID)          │
      ├── file_events   ──► rule engine ───────────────┤
      └── proc_events   ──► rule engine ───────────────┤
                                                       ▼
                                                  SSE /stream
                                                       │
                                                    browser
```

`RAW_TRACEPOINT_PROBE` is used instead of `TRACEPOINT_PROBE` because BCC cannot
generate the argument struct on kernel 7.0 — the filename is read straight from
the CPU registers (`RSI` for `openat`, `RDI` for `execve`).

## The syscall ABI problem

The single most important detail in this project.

ADFA-LD was captured on **Ubuntu 11.04, 32-bit**, so its traces use **i686**
syscall numbers. Our sensor runs on **x86-64**. The same operations are
numbered differently:

| operation | x86-64 | i686 |
|---|---|---|
| `read` | 0 | 3 |
| `write` | 1 | 4 |
| `openat` | 257 | 5 (`open`) |
| `execve` | 59 | 11 |

Without translation the model reads `read` as `restart_syscall` and `openat` as
`remap_file_pages` — patterns it never trained on, so its score is meaningless.
`ml/syscall_map.json` maps the two ABIs by syscall **name**.

Measured effect on separation between normal and attack scores:

```
without translation   +0.504
with translation      +0.717      42 % better
```

Full derivation in `ml/01_explore_dataset.ipynb`.

## Watching the model live

The dashboard has an **LSTM Engine** panel showing what the model is doing
right now — not just when it alerts:

```
🤖 LSTM Engine  [CUDA]     6 tracked · 6 full windows · 525 inferences · alert ≥ 90%

  malware_sim  1004  ████████████████████  99%     <- anomaly
  data_stealer 1005  ████████████████████  97%     <- anomaly
  curl         1001  ████████████████████  47%
  bash         1003  ████████████████████   2%
```

Each row is a process the model is buffering. The bar is how full its
100-syscall window is, colour-coded by what that window is good for:

| Bar | Window | Meaning |
|---|---|---|
| grey | < 50 syscalls | too short to score |
| purple | 50–99 | score shown, but cannot alert |
| blue | 100 | full window — alert-grade |

Served by `/api/ml`, polled every 1.5 s. This matters because the score badge in
the event log only appears when a process *also* opens a file — on a quiet
system the model looks idle when it is actually working.

## Detection settings

| Setting | Value | Why |
|---|---|---|
| Alert threshold | 0.9 | 0.5 fires too often on live traffic |
| Window to alert | 100 syscalls | shorter windows are mostly padding |
| Window to display | 50 syscalls | below this the score misleads |
| Inference stride | 50 syscalls | the window is a deque — without a stride it re-scores on *every* syscall |
| Alert cooldown | 60 s per PID | stops one process flooding the log |
| Alert on | transition only | a busy process shouldn't re-alert while it stays anomalous |
| Whitelist | applies to ML too | systemd/chrome/VS Code are busy, not malicious |
| Auto-calibration | first 90 s | learns *this* machine's normal, then sets the bar above it |
| Burst sampling | 128 of every 1024 | one event per syscall overflows the perf ring |
| Noise paths | excluded from rate rule | `/proc`, `/sys`, `/dev/cpu` are polled by design, not stolen |

### Why the sensor samples in bursts

Tracing every syscall system-wide produces >100 k perf events/second. Python
cannot drain that, so the ring overflows and the kernel prints
`Possibly lost N samples` — tens of thousands at a time. The stream was being
lost anyway, just invisibly.

Sampling every Nth syscall would be worse: the LSTM was trained on *consecutive*
sequences, and a decimated stream destroys the ordering it reads. So the sensor
emits **128 consecutive syscalls per PID, then stays silent for the next 896**.
Each burst is an unbroken run long enough to fill the 100-syscall window, at
12.5 % of the event rate. Drops that still occur are counted and shown in the
LSTM Engine panel rather than only on the console.

All three perf buffers (`file_events`, `proc_events`, `syscall_events`) get an
explicit size and a shared lost-sample handler. BCC's default is an 8-page ring
whose built-in handler prints `Possibly lost N samples` directly to stderr —
with `openat` alone running tens of thousands per second, that default is what
produces most of the console noise.

### Kernel pseudo-filesystems

`nvidia-powerd` reads `/dev/cpu/N/msr` continuously for power management, and
`systemd-oomd` walks `/sys/fs/cgroup`. Both trip a naive "50 file opens per
second" rule immediately, producing endless *possible exfiltration* alerts for
routine housekeeping. Paths under `/proc`, `/sys`, `/dev/cpu` and friends are
therefore excluded from the rate counter — they are kernel interfaces, not user
data. They are still logged, and still matched against `SENSITIVE_PATHS`.

### Why auto-calibration exists

The LSTM was trained on ADFA-LD — Ubuntu 11.04, 2011. Modern desktop software
makes syscall sequences that era never produced: Chrome and VS Code run huge
`epoll`/`futex` loops, systemd behaves nothing like 2011 init. The syscall
*vocabulary* still maps fine (14 of 17 common modern calls appear in training
data), but the *sequences* are alien, so the model scores almost everything
above 0.9 and the log floods.

Raising a fixed threshold does not fix this — when normal traffic already sits
at 0.99, no hand-picked constant separates it from an attack. So on startup the
detector spends 90 seconds scoring without alerting, then sets the threshold
just above the 99.5th percentile of what it saw. Alerts resume automatically.

This is a real limitation of using a 2011 dataset against a 2026 desktop, not a
bug. If you want to see the model fire reliably, demo mode replays genuine
ADFA-LD attack traces.

At a 15-syscall window the false-positive rate is ~78 %; at 100 it is ~19 % with
detection essentially unchanged. Measured in `ml/04_live_inference.ipynb`.

## Model performance

| | Isolation Forest | LSTM + Attention |
|---|---|---|
| Supervision | none (normal only) | labelled |
| Features | 450-dim frequency vector | raw sequence, 200 steps |
| Parameters | 200 trees | 262 K (~1 MB) |
| Hardware | CPU, seconds | RTX 3050, 2–4 min, ~150 MB VRAM |
| Validation AUC | — | **0.9854** |
| Attack recall | modest | 96–98 % |

## Retraining

See `ml/README.md`. Short version:

```bash
venv/bin/python3 -m jupyter lab ml/     # run 01 → 02 → 03 → 04
```

Equivalent scripts, if you prefer no notebook:

```bash
venv/bin/python3 ml/train_model.py      # Isolation Forest
venv/bin/python3 ml/lstm_train.py       # LSTM
```

## Setup notes

**`run.sh` sets `PYTHONPATH` on purpose.** eBPF needs root, but `sudo` resets
`$HOME` to `/root`, and Python derives its per-user `site-packages` from
`$HOME`. Anything installed with `pip install --user` — including `torch` —
becomes invisible to root, silently disabling the model. Passing `PYTHONPATH`
explicitly keeps those packages reachable.

**The sensor skips its own PID.** Reading the perf buffer issues syscalls; if
those were traced they would generate more events, which take more syscalls to
read — a feedback loop that floods the ring buffer. `SELF_PID` is substituted
into the C source at load time.

**Requirements:** BCC (`python3-bpfcc`), Flask, PyTorch with CUDA,
scikit-learn, joblib. Dataset: [ADFA-LD](https://research.unsw.edu.au/projects/adfa-ids-datasets)
at `~/Downloads/ADFA-LD`.
