/*
 * bcc_intellisense_stubs.h
 * ========================
 * IntelliSense-only stubs for BCC / eBPF macros.
 *
 * BCC injects its own definitions at compile time, so this file is wrapped in
 * #ifdef __INTELLISENSE__ — the real BCC compiler never sees it.
 * VS Code's C/C++ extension defines __INTELLISENSE__ automatically, so these
 * stubs make the editor happy without affecting the running program at all.
 *
 * What each stub does:
 *  - Defines kernel primitive types  (u8, u16, u32, u64, __user, ...)
 *  - Stubs BPF map macros            (BPF_HASH, BPF_PERF_OUTPUT)
 *  - Stubs the tracepoint probe macros
 *  - Provides bpf_raw_tracepoint_args so "ctx->args[n]" is understood
 */

#ifndef BCC_INTELLISENSE_STUBS_H
#define BCC_INTELLISENSE_STUBS_H

#ifdef __INTELLISENSE__

/* ── Kernel integer typedefs ─────────────────────────────────────────────── */
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed   char      s8;
typedef signed   short     s16;
typedef signed   int       s32;
typedef signed   long long s64;

/* ── Address-space annotation (kernel vs user space pointers) ────────────── */
#define __user
#define __kernel

/* ── Process name buffer size ────────────────────────────────────────────── */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* ── Raw tracepoint context ──────────────────────────────────────────────── */
struct bpf_raw_tracepoint_args {
    unsigned long args[6];
};

/* ── BPF map stubs ───────────────────────────────────────────────────────── */

/*
 * BPF_HASH(name, key_type, val_type)
 * Expands to a struct with the helper methods that BCC maps expose.
 * Only the method signatures IntelliSense cares about are listed.
 */
#define BPF_HASH(name, key_type, val_type)                      \
    struct _bpf_hash_##name {                                   \
        val_type *(*lookup)(key_type *key);                     \
        val_type *(*lookup_or_try_init)(key_type *k, val_type *v); \
        int (*update)(key_type *k, val_type *v);                \
        int (*delete)(key_type *k);                             \
    } name

/*
 * BPF_PERF_OUTPUT(name)
 * Expands to a struct whose only visible method is perf_submit().
 */
#define BPF_PERF_OUTPUT(name)                                   \
    struct _bpf_perf_##name {                                   \
        int (*perf_submit)(void *ctx, void *data, int size);    \
    } name

/* ── Tracepoint probe macros ─────────────────────────────────────────────── */

/*
 * RAW_TRACEPOINT_PROBE(event)
 * BCC turns this into a function declaration with a "ctx" parameter.
 * We replicate that so IntelliSense knows "ctx" exists inside the body.
 */
#define RAW_TRACEPOINT_PROBE(event)                                     \
    int bpf_func_raw_##event(struct bpf_raw_tracepoint_args *ctx)

/*
 * TRACEPOINT_PROBE(category, event)
 * Kept here in case any old code still uses it.
 */
#define TRACEPOINT_PROBE(category, event) \
    int bpf_func_##category##_##event(void *args)

/* ── BPF helper function stubs ───────────────────────────────────────────── */
static inline u64  bpf_get_current_pid_tgid(void)             { return 0; }
static inline u64  bpf_get_current_uid_gid(void)              { return 0; }
static inline int  bpf_get_current_comm(void *buf, int size)  { return 0; }
static inline int  bpf_probe_read_kernel(void *dst, int size, const void *src) { return 0; }
static inline int  bpf_probe_read_user(void *dst, int size, const void *src)   { return 0; }
static inline int  bpf_probe_read_user_str(void *dst, int size, const void *src) { return 0; }

#endif /* __INTELLISENSE__ */
#endif /* BCC_INTELLISENSE_STUBS_H */
