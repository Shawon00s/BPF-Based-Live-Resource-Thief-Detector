// eBPF Kernel-Space Sensor
// ========================
// Uses RAW_TRACEPOINT_PROBE(sys_enter) for kernel 7.0 compatibility.
//
// Three perf ring-buffers:
//   file_events    – detailed openat events  (rule engine + UI log)
//   proc_events    – detailed execve events  (rule engine + UI log)
//   syscall_events – compact (pid, syscall_nr) for every syscall  ← LSTM feed
//
// The LSTM gets ALL syscall numbers so it can build a proper 100-syscall
// sliding window per PID, matching what it was trained on (ADFA-LD).

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// IntelliSense-only stubs — BCC never sees this file
#ifdef __INTELLISENSE__
#include "bcc_intellisense_stubs.h"
#endif

// x86-64 syscall numbers (stable ABI)
#define __NR_openat  257
#define __NR_execve   59

// Replaced with the dashboard's real PID by dashboard.py at load time.
// The fallback keeps the file valid for standalone syntax checks.
#ifndef SELF_PID
#define SELF_PID 0
#endif

// ─── Event Structs ────────────────────────────────────────────────────────────

// Rich event for every openat() — sent to rule engine and UI
struct file_event_t {
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

// Rich event for every execve() — sent to rule engine and UI
struct proc_event_t {
    u32  pid;
    u32  ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

// Compact event for EVERY syscall — fed into the LSTM sliding window
struct syscall_event_t {
    u32 pid;
    u32 syscall_nr;
};

// ─── eBPF Maps ────────────────────────────────────────────────────────────────

BPF_PERF_OUTPUT(file_events);      // openat details → rule engine
BPF_PERF_OUTPUT(proc_events);      // execve details → rule engine
BPF_PERF_OUTPUT(syscall_events);   // (pid, syscall_nr) → LSTM predictor

// Per-PID openat counter — lets user space detect high-frequency file access
BPF_HASH(read_count, u32, u64);

// ─── Main Hook ────────────────────────────────────────────────────────────────
//
// Fires on EVERY syscall entry.  We:
//   1. Always emit a compact syscall_event_t  (for LSTM)
//   2. For openat: also emit detailed file_event_t
//   3. For execve: also emit detailed proc_event_t
//
// x86-64 register convention at syscall entry:
//   syscall arg1  →  rdi  (regs->di)
//   syscall arg2  →  rsi  (regs->si)

RAW_TRACEPOINT_PROBE(sys_enter) {
    long syscall_nr = (long)ctx->args[1];
    u32  pid        = bpf_get_current_pid_tgid() >> 32;

    // ── 0. Exclude the detector itself ────────────────────────────────────────
    // CRITICAL: reading the perf buffer from user space issues its own syscalls.
    // Without this guard those syscalls are traced too, which generates more
    // events, which take more syscalls to read — a runaway feedback loop that
    // saturates the ring buffer and starves the real events we care about.
    // SELF_PID is substituted by dashboard.py before compilation.
    if (pid == SELF_PID)
        return 0;

    // ── 1. LSTM feed: emit compact event for every user-space syscall ──────────
    // Filter: pid > 1 skips the idle task; syscall_nr < 400 stays in ABI range.
    if (pid > 1 && syscall_nr >= 0 && syscall_nr < 400) {
        struct syscall_event_t sc = {};
        sc.pid        = pid;
        sc.syscall_nr = (u32)syscall_nr;
        syscall_events.perf_submit(ctx, &sc, sizeof(sc));
    }

    // ── 2. Detailed events: only for openat and execve ─────────────────────────
    if (syscall_nr != __NR_openat && syscall_nr != __NR_execve)
        return 0;

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    const char __user *ufilename = NULL;

    if (syscall_nr == __NR_openat) {
        // openat: filename is arg2 → RSI
        bpf_probe_read_kernel(&ufilename, sizeof(ufilename), &regs->si);
    } else {
        // execve: filename is arg1 → RDI
        bpf_probe_read_kernel(&ufilename, sizeof(ufilename), &regs->di);
    }

    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (syscall_nr == __NR_openat) {
        struct file_event_t event = {};
        event.pid = pid;
        event.uid = uid;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        if (ufilename)
            bpf_probe_read_user_str(event.filename, sizeof(event.filename), ufilename);

        u64 zero = 0;
        u64 *cnt = read_count.lookup_or_try_init(&pid, &zero);
        if (cnt) (*cnt)++;

        file_events.perf_submit(ctx, &event, sizeof(event));

    } else {  // __NR_execve
        struct proc_event_t event = {};
        event.pid  = pid;
        event.ppid = (u32)bpf_get_current_pid_tgid();
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        if (ufilename)
            bpf_probe_read_user_str(event.filename, sizeof(event.filename), ufilename);

        proc_events.perf_submit(ctx, &event, sizeof(event));
    }

    return 0;
}
