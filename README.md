# BPF-Based Live Resource Thief Detector

OS Course Project | Ubuntu 26.04 | Kernel 7.0

## Project Structure

```
Project/
├── src/
│   ├── ebpf_sensor.c       # Kernel-space eBPF probe (C)
│   ├── detector.py         # User-space detector + alerts (Python)
│   └── simulate_thief.py   # Attack simulator for testing
├── logs/
└── reports/                # Auto-generated session reports
```

## How to Run

### Terminal 1 — Start the Detector (needs root)
```bash
cd ~/Downloads/Project/src
sudo python3 detector.py
```

### Terminal 2 — Simulate a Thief
```bash
cd ~/Downloads/Project/src

# Test sensitive file snooping
python3 simulate_thief.py snoop

# Test rapid file access (exfiltration simulation)
python3 simulate_thief.py rapid --count 100

# Both scenarios
python3 simulate_thief.py both
```

## Detection Logic

| Alert Type | Trigger Condition |
|---|---|
| ALERT | Process accesses `/etc/passwd`, `/.ssh/`, `.key`, etc. |
| ALERT | Process opens >50 files per second (exfiltration) |
| WARN  | Suspicious binary executed (nc, curl, python, etc.) |
| INFO  | Any new process creation |

## Tech Stack

- **Kernel Space**: eBPF C (compiled by BCC at runtime)
- **User Space**: Python 3 + BCC bindings
- **Syscalls Hooked**: `openat`, `execve`
- **IPC**: eBPF perf ring buffers (zero-copy kernel→user)

## Architecture Diagram

```
┌─────────────────────────────────────────────┐
│                 USER SPACE                   │
│  detector.py                                 │
│  ┌──────────────┐   ┌──────────────────────┐│
│  │ Detection    │   │  Alert / Report      ││
│  │ Logic        │   │  Engine              ││
│  └──────┬───────┘   └──────────────────────┘│
│         │ reads                              │
└─────────┼───────────────────────────────────┘
          │  eBPF Maps (perf ring buffer)
┌─────────┼───────────────────────────────────┐
│         │          KERNEL SPACE             │
│  ┌──────▼───────────────────────────┐       │
│  │  ebpf_sensor.c                   │       │
│  │  • TRACEPOINT openat  → file_events│     │
│  │  • TRACEPOINT execve  → proc_events│     │
│  └──────────────────────────────────┘       │
│  Linux Kernel 7.0 / eBPF VM                 │
└─────────────────────────────────────────────┘
```
