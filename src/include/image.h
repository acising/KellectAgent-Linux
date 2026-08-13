// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phase 2 #2: image/executable load detection module header.
// Mirrors the per-module header convention of process.h (independent enum +
// struct Event + Arguments/Event structs, so the image module can build
// standalone without pulling in all.h).

#ifndef KELLECT_LINUX_IMAGE_H
#define KELLECT_LINUX_IMAGE_H

#define TASK_COMM_LEN 64
#define MAX_FILENAME_LEN 127

/* mmap protection flags — UAPI stable values from <asm-generic/mman-common.h>.
 * Defined here because BPF side has no libc headers; the values never change
 * across kernels (part of the user-space ABI). */
#define PROT_READ  0x1   /* Page can be read.  */
#define PROT_WRITE 0x2   /* Page can be written.  */
#define PROT_EXEC  0x4   /* Page can be executed.  */

typedef unsigned int __u32;
typedef __u32 u32;

enum EventType
{
    /* Phase 2 #2: dedicated image namespace (401+) to avoid collision with
     * EVENT_PROCESS_* (1-21). Stage 1 covers PROT_EXEC mmap; Stage 2 adds
     * mprotect(PROT_EXEC) — RW->RWX on existing memory, the injection pattern.
     * 差距 #3 (2026-08-23) adds unload tracking + kernel module load/unload. */
    EVENT_IMAGE_LOAD = 401,
    EVENT_IMAGE_MPROTECT = 402,
    EVENT_IMAGE_UNLOAD = 403,
    EVENT_IMAGE_MODULE_LOAD = 404,
    EVENT_IMAGE_MODULE_UNLOAD = 405
};


struct Event {

    // ========================== basic information ==========================
    // process id
    int pid;

    // parent process id
    int ppid;

    // process name
    char comm[TASK_COMM_LEN];

    // event type
    int event_type;

    // process or thread
    bool is_process;

    // ========================== running information ==========================

    // spend time on user mode for now
    long long unsigned int user_mode_time;

    // spend time on kernel mode for now
    long long unsigned int kernel_mode_time;

    // the count of voluntary context switch
    unsigned long voluntary_context_switch_count;

    // the count of involuntary context switch
    unsigned long involuntary_context_switch_count;

    // the time since process start, exclude sleeping time
    long long unsigned int start_time;

    // ========================== user information ==========================

    // real UID of the task
    uid_t uid;

    // real GID of the task
    gid_t gid;

    // effective UID of the task
    uid_t euid;

    // effective GID of the task
    gid_t egid;

    char filename[MAX_FILENAME_LEN];

};

/* Phase 2 #2: mmap PROT_EXEC event arguments.
 * Fields mirror the mmap syscall signature (addr/len/prot/flags/fd/off) so the
 * BPF handler can fill them directly from ctx->args[]. The file path is NOT
 * captured here — bpf_d_path is unavailable in tracepoint programs. The
 * userspace handler resolves fd → path via /proc/<pid>/fd/<fd> readlink. */
struct ImageLoadArguments {
    unsigned long addr;     /* desired mapping address (usually NULL) */
    unsigned long len;      /* mapping length */
    unsigned long prot;     /* protection flags (must include PROT_EXEC) */
    unsigned long flags;    /* mmap flags (MAP_PRIVATE, MAP_ANONYMOUS, ...) */
    int fd;                 /* backing file descriptor (-1 for anonymous) */
    unsigned long off;      /* offset within the backing file */
};

struct ImageLoadEvent {
    struct Event event;
    struct ImageLoadArguments imageLoadArguments;
};

/* Phase 2 #2 Stage 2: mprotect(PROT_EXEC) event arguments.
 * Fields mirror the mprotect(addr, len, prot) syscall signature. There is no
 * fd argument — the userspace handler resolves the path from
 * /proc/<pid>/maps by addr alone (anonymous region => "<anonymous>", the
 * strongest injection signal: executable rights granted to heap/JIT memory). */
struct ImageMprotectArguments {
    unsigned long addr;     /* page-aligned address being re-protected */
    unsigned long len;      /* length */
    unsigned long prot;     /* new protection flags (must include PROT_EXEC) */
};

struct ImageMprotectEvent {
    struct Event event;
    struct ImageMprotectArguments imageMprotectArguments;
};

/* 差距 #3: munmap of a tracked executable mapping (unload detection).
 * The BPF side keeps an LRU registry of {tgid, addr} -> len for every
 * PROT_EXEC mapping/mprotect it reported; munmap reports only exact-key hits.
 * Known misses (accepted v1): partial unmaps (sub-range), non-MAP_FIXED addr
 * drift (kernel relocated the mapping), LRU eviction under pressure. */
struct ImageUnloadArguments {
    unsigned long addr;     /* munmap start address (matched the registry key) */
    unsigned long len;      /* munmap length (syscall arg, may differ from registered) */
};

struct ImageUnloadEvent {
    struct Event event;
    struct ImageUnloadArguments imageUnloadArguments;
};

/* 差距 #3: kernel module load/unload (rootkit surface). ctx name arrives as a
 * __data_loc dynamic string — read the same way as sched_process_exec's
 * __data_loc_filename (offset & 0xFFFF from ctx start). */
struct ImageModuleLoadArguments {
    char name[64];          /* module name (kernel-side authoritative) */
    unsigned int taints;    /* kernel taint flags after load */
};

struct ImageModuleLoadEvent {
    struct Event event;
    struct ImageModuleLoadArguments imageModuleLoadArguments;
};

struct ImageModuleUnloadArguments {
    char name[64];
};

struct ImageModuleUnloadEvent {
    struct Event event;
    struct ImageModuleUnloadArguments imageModuleUnloadArguments;
};

#endif /* KELLECT_LINUX_IMAGE_H */
