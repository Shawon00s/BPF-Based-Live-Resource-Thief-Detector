# BPF Based Live Resource Thief Detector

**Operating Systems Course Project** · Ubuntu 26.04 · Kernel 7.0 · RTX 3050

A live monitor that watches **every system call** on the machine and flags any
process behaving like it is stealing data: reading private keys, sweeping the
filesystem, or spawning suspicious children.

The core idea is an operating systems idea. A program can hide its name, its
window and its file on disk, but it cannot avoid asking the kernel for what it
needs. The system call boundary is the one place where a process has to tell
the truth about what it is doing.

---

## Operating systems concepts demonstrated

This table is the quickest way to see what the project covers and where.

| OS concept | Where it lives | What it does |
|---|---|---|
| **System calls** | [src/ebpf_sensor.c](src/ebpf_sensor.c) | Intercepts `sys_enter` for every syscall; names `openat` (257) and `execve` (59) |
| **Kernel space vs user space** | [src/ebpf_sensor.c](src/ebpf_sensor.c) + [src/dashboard.py](src/dashboard.py) | C runs in the kernel, Python in user space, joined by perf ring buffers |
| **Calling conventions** | `ebpf_sensor.c` line 132 | Reads arguments from RDI and RSI registers directly |
| **Kernel to user IPC** | `BPF_PERF_OUTPUT` × 3 | Three lock free ring buffers carry events out of the kernel |
| **Kernel data structures** | `BPF_HASH` × 2 | Per process counters kept in kernel hash maps |
| **Threads** | [src/detector.py](src/detector.py) lines 457 to 461 | Five threads, one job each |
| **Producer and consumer** | `detector.py` lines 54 to 56 | Three bounded `queue.Queue` objects between stages |
| **Mutual exclusion** | `detector.py` line 59 | One `threading.Lock` guards all shared counters |
| **Thread coordination** | `detector.py` lines 67, 422 | `threading.Event` for shutdown, `wait(timeout)` instead of `sleep` |
| **Buffering and backpressure** | `ebpf_sensor.c` lines 80 to 81 | Burst sampling stops the ring buffer overflowing |
| **Process identity** | `struct file_event_t` | PID, UID and `comm` captured in kernel at syscall time |

---

## Running it

```bash
cd ~/Downloads/Project
bash run.sh                 # needs root, eBPF loads into the kernel
```

Then open **http://localhost:5000**

Expected on startup:

```
[ML] LSTM loaded on cuda | AUC=0.9834
[ML] Syscall ABI map loaded: 376 x86_64 to i686 translations
[ML] LSTM model loaded — real-time anomaly scoring enabled
```

The first **90 seconds are calibration**, during which no ML alerts fire. This
is deliberate and explained below.

**Trigger a detection** in a second terminal:

```bash
venv/bin/python3 src/simulate_thief.py snoop    # reads /etc/passwd
venv/bin/python3 src/simulate_thief.py rapid    # opens 100 files fast
```

**Terminal only version**, no web interface, five threads visible in the log:

```bash
sudo venv/bin/python3 src/detector.py
```

**Without root**, the tool falls back to demo mode and replays real attack
traces from the dataset. Useful for showing the model fire on demand:

```bash
venv/bin/python3 src/dashboard.py
```

---

## How a system call becomes an alert

```
  a process calls openat("/etc/shadow")
            |
  ==========|=================================  kernel space
            v
  RAW_TRACEPOINT_PROBE(sys_enter)        our eBPF program
            |
            +--> file_events      ring buffer   (openat details)
            +--> proc_events      ring buffer   (execve details)
            +--> syscall_events   ring buffer   (numbers for the model)
            |
  ==========|=================================  user space
            v
      perf_buffer_poll()
            |
            +--> rule engine   sensitive paths, open rate
            +--> LSTM          sliding window of 100 syscalls
                        |
                        v
                   alert on the dashboard
```

### Why `RAW_TRACEPOINT_PROBE` and not `TRACEPOINT_PROBE`

The usual helper hands you a struct with named fields, so you can write
`args->filename`. On kernel 7.0 that struct is incomplete and the build fails.

The raw variant gives no named fields at all, only a pointer to the CPU
registers as they were at syscall entry. The x86 64 convention puts the first
argument in **RDI** and the second in **RSI**, so:

| syscall | argument wanted | register |
|---|---|---|
| `openat(dfd, filename, ...)` | 2nd | RSI |
| `execve(filename, argv, envp)` | 1st | RDI |

This depends only on the processor convention, which does not change between
kernel versions, so the same code works from kernel 4.18 to 7.x.

---

## Concurrency design

The first version was a single loop: read a record, check it, print it, repeat.
It failed, and the failure is the interesting part.

Printing to a terminal is slow. While the program was printing, **nobody was
draining the kernel ring buffer**, so the kernel filled it and discarded
records. Being slow did not make the answers late. It made them wrong, because
the data was gone before it was ever read.

```
Thread 1          Thread 2          Thread 3
BPF Poller  --->  Rule Engine  --->  ML Engine
            raw_queue      ml_queue
   |                |                  |
   |                +---------+--------+
   |                          v
   |                    alert_queue
   |                     |        |
   |                     v        v
   |               Thread 4    Thread 5
   |               Printer     Reporter
   |
 never blocked by anything downstream
```

| Thread | Job | Why it is separate |
|---|---|---|
| 1 BPF Poller | Drains the kernel ring buffer | Must never wait on anything |
| 2 Rule Engine | Path and rate checks | CPU work, keep off the poller |
| 3 ML Engine | LSTM inference on the GPU | Slowest stage by far |
| 4 Alert Printer | Terminal output | Terminal I/O is slow |
| 5 Report Writer | Saves a report every 60 s | Disk I/O is slow |

Three decisions matter, and each is a standard OS idea:

**Bounded queues.** Every queue has a maximum size (2000, 500, 1000). When a
consumer falls behind, the producer drops the oldest item rather than blocking.
Losing one stale record is far cheaper than stalling the thread that reads the
kernel, because a stalled reader loses thousands.

**One lock, not several.** A single `state_lock` protects every shared counter
and set. Using one lock instead of a lock per structure keeps the code simple
and makes deadlock impossible, since a thread never holds one lock while
waiting for another.

**Event flag instead of sleep.** The report writer wakes every 60 seconds. With
`time.sleep(60)` a Control C would take up to a minute to take effect. Instead
it calls `shutdown_event.wait(timeout=60)`, so setting the event wakes every
thread at once and the tool exits immediately after writing its final report.

---

## Buffering: why the sensor samples in bursts

Tracing every syscall system wide produces **over 100,000 perf events per
second**. User space Python cannot drain that, so the ring overflowed and the
kernel reported `Possibly lost N samples`, sometimes 45,000 at a time. The data
was being thrown away regardless.

Keeping every Nth call would be worse. The model reads **consecutive**
sequences, and a decimated stream destroys the ordering it depends on.

So the kernel program emits in bursts: **128 consecutive syscalls per process,
then silence for the next 896**. Each burst is an unbroken run long enough to
fill the model's 100 call window, at 12.5 percent of the event rate.

All three ring buffers are also given an explicit size and a shared lost sample
handler. BCC's default is an 8 page ring whose built in handler prints straight
to stderr, which was the source of most of the console noise.

---

## Detection layers

### Layer 1: rules

| Rule | Threshold |
|---|---|
| Sensitive path touched | `/etc/shadow`, `/.ssh/`, `.pem`, `id_rsa`, and similar |
| File open rate | more than 50 per second per process |
| Suspicious child process | `ncat`, `socat`, `curl`, and similar via `execve` |

Two refinements came out of testing:

**Sensitive paths are checked before the whitelist.** The whitelist exists to
silence processes that are merely *busy*. Reading `/etc/shadow` is a different
kind of signal and is never suppressed, whitelisted or not.

**Kernel pseudo filesystems do not count toward the rate rule.** `nvidia-powerd`
reads `/dev/cpu/N/msr` continuously for power management and `systemd-oomd`
walks `/sys/fs/cgroup`. Both trip a naive rate rule instantly. Paths under
`/proc`, `/sys` and `/dev/cpu` are kernel interfaces, not user data.

### Layer 2: the model

An LSTM with attention, trained on **ADFA LD**, a public dataset of Linux
syscall traces containing normal behaviour and six attack families.

```
100 syscall numbers -> Embedding(351,64) -> LSTM(64,128) x2
                    -> Attention -> Linear(128,64,1) -> score 0.0 to 1.0
```

262,402 parameters, about 1 MB, roughly 150 MB of VRAM while training, about
three minutes on the RTX 3050. Validation AUC **0.9834**.

Reading the sequence *in order* is the point. A simpler Isolation Forest
baseline only counted how often each call appeared, so it could not tell a
program that opens one file from one that opens five hundred.

---

## The syscall ABI problem

The single most important detail in the project, and the hardest bug.

ADFA LD was recorded in 2011 on **32 bit Ubuntu**, so its traces use **i686**
syscall numbers. Our sensor runs on **x86 64**. The same operations are
numbered differently:

| operation | x86 64 | i686 |
|---|---|---|
| `read` | 0 | 3 |
| `write` | 1 | 4 |
| `openat` | 257 | 5 (`open`) |
| `execve` | 59 | 11 |

Untranslated, the model read `read` as `restart_syscall` and `openat` as
`remap_file_pages`, patterns it had never trained on. Nothing crashed, because
the numbers were valid on both sides. The scores were simply meaningless.

[ml/syscall_map.json](ml/syscall_map.json) maps the two interfaces **by syscall
name**, 376 entries. Measured effect on the gap between normal and attack
scores:

```
without translation   +0.16
with translation      +0.77
```

Full derivation in [ml/01_explore_dataset.ipynb](ml/01_explore_dataset.ipynb).

---

## Tuning constants, and why each one is what it is

| Setting | Value | Reason |
|---|---|---|
| Window to alert | 100 syscalls | at 15 the buffer is mostly padding and 78 percent of normal traffic is flagged |
| Window to display | 50 syscalls | below this the score misleads |
| Inference stride | 50 syscalls | the buffer is a fixed size deque; without a stride it rescores on *every* call |
| Alert threshold | 0.9, then calibrated | see below |
| Alert cooldown | 60 s per PID | a busy process should not re alert while it stays anomalous |
| Burst sampling | 128 of every 1024 | one event per syscall overflows the perf ring |
| File rate | 50 per second | above normal application behaviour |

### Why the threshold calibrates itself

The model learned what normal looked like in 2011. Modern software does not
behave that way: Chrome and VS Code run enormous `epoll` and `futex` loops that
the training set never contained. Almost everything scored above 0.9.

Raising a fixed threshold does not help when normal traffic already sits at
0.99. So the detector spends its first 90 seconds scoring without alerting,
collects the distribution on the machine it is actually running on, and sets
the bar just above the 99.5th percentile of that. Normal traffic raising an
alert fell from **87 percent to 3**.

This is a genuine limitation of using a 2011 dataset against a 2026 desktop,
not something tuning can fully fix.

---

## Results

| Measured | Before | After |
|---|---|---|
| Records lost per second by the kernel buffer | 45,646 | 0 |
| Model runs per 1000 syscalls, one process | 901 | 19 |
| Gap between normal and attack scores | 0.16 | 0.77 |
| Normal traffic raising a false alert | 87 percent | 3 percent |
| Attacks correctly detected | 93 percent | 93 percent |

The last row is the one that matters. Every change that reduced noise was
checked against detection, and detection held.

---

## Project layout

```
Project/
├── src/
│   ├── ebpf_sensor.c        kernel program, RAW_TRACEPOINT on sys_enter
│   ├── dashboard.py         web version, Flask and server sent events
│   ├── detector.py          terminal version, the five thread pipeline
│   ├── simulate_thief.py    attack simulator for testing
│   └── templates/index.html live interface
├── ml/
│   ├── 01_explore_dataset.ipynb    dataset and the ABI discovery
│   ├── 02_isolation_forest.ipynb   unsupervised baseline
│   ├── 03_lstm_train.ipynb         GPU sequence model
│   ├── 04_live_inference.ipynb     validation and threshold tuning
│   ├── live_predictor.py           the live scorer dashboard.py imports
│   ├── syscall_map.json            376 x86 64 to i686 translations
│   └── saved_model/                trained weights
├── reports/                 auto saved session reports
└── run.sh                   launcher, handles sudo and PYTHONPATH
```

The five thread pipeline lives in `detector.py`. `dashboard.py` uses a simpler
threading model because Flask handles request concurrency itself.

Notebooks are documented separately in [ml/README.md](ml/README.md).

---

## Setup notes

**`run.sh` sets `PYTHONPATH` on purpose.** eBPF needs root, but `sudo` resets
`$HOME` to `/root`, and Python derives its per user `site-packages` from
`$HOME`. Anything installed with `pip install --user`, including `torch`,
becomes invisible to root and the model silently fails to load.

**The sensor skips its own PID.** Reading the perf buffer issues syscalls. If
those were traced they would generate more events, which take more syscalls to
read, a feedback loop that saturates the ring. `SELF_PID` is substituted into
the C source at load time.

**Requirements:** BCC (`python3-bpfcc`), Flask, PyTorch with CUDA,
scikit-learn, joblib. Dataset:
[ADFA LD](https://research.unsw.edu.au/projects/adfa-ids-datasets) at
`~/Downloads/ADFA-LD`.
