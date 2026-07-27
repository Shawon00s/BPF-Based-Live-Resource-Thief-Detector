// eBPF Kernel-Space Sensor
// Hooks into syscalls to collect process behavior data

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// ─── Shared Data Structures ───────────────────────────────────────────────────

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];   // process name (max 16 chars)
    char filename[256];
};

struct proc_event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

struct net_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 daddr;   // destination IP
    u16 dport;   // destination port
};

// ─── eBPF Maps (Kernel ↔ User Space communication) ───────────────────────────

// Ring buffers for streaming events to user space
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(proc_events);
BPF_PERF_OUTPUT(net_events);

// Counter map: how many times each PID read a file
BPF_HASH(read_count, u32, u64);

// ─── Hook 1: Track file open (openat syscall) ─────────────────────────────────

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct file_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read filename from user-space pointer safely
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    // Increment per-PID read counter
    u64 zero = 0;
    u64 *count = read_count.lookup_or_try_init(&event.pid, &zero);
    if (count) {
        (*count)++;
    }

    file_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// ─── Hook 2: Track new process creation (execve syscall) ─────────────────────

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct proc_event_t event = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid  = pid_tgid >> 32;
    event.ppid = (u32)bpf_get_current_pid_tgid(); // simplified

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    proc_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
