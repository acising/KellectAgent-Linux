// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phase 2 #2: image/executable load detection — BPF side.
//
// Hook: tp/syscalls/sys_enter_mmap, filtered to prot & PROT_EXEC.
// This catches every loading of a executable-backed mapping (ELF .text / .so
// load by ld.so, dlopen, manual mmap of executable files) and also anonymous
// executable mappings (JIT compilers, packers, shellcode) — the EDR-relevant
// subset of mmap that the unfiltered process-module mmap handler does NOT
// isolate.
//
// File path resolution: bpf_d_path is only allowed in BPF_PROG_TYPE_TRACING
// (fentry/fexit/lsm), not in tracepoint programs. So the handler stores the fd
// and lets userspace resolve /proc/<pid>/fd/<fd> via readlink.

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../../include/image.h"

/* ringbuf: 16 MB — the value validated as safe on both 信创 hosts by the
 * all/user modules (kellect-ebpf skill §3). 512 MB is a定时炸弹 on low-memory
 * hosts (B 阶段 user EINVAL). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} rb SEC(".maps");

/* 差距 #3 unload tracking, two-stage:
 * 1) sys_enter_mmap (PROT_EXEC filtered) stashes {len} in mmap_args_map;
 *    sys_exit_mmap registers {tgid -> actual base} into exec_maps (the mmap
 *    request addr is usually a NULL hint — only the retval is the real base).
 * 2) sys_enter_mprotect registers directly (its addr IS the live mapping).
 * sys_enter_munmap then reports only exact-key hits. LRU keeps the registry
 * bounded; misses (partial unmap, eviction) documented in image.h. */
struct mmap_pending {
    unsigned long len;
};

struct exec_map_key {
    __u64 tgid;
    unsigned long addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);                /* pid_tgid */
    __type(value, struct mmap_pending);
} mmap_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct exec_map_key);
    __type(value, unsigned long);      /* registered mapping length */
} exec_maps SEC(".maps");

/* Phase 2 #2 Stage 1: PROT_EXEC mmap detector.
 * Triggered on every mmap entry, returns early for non-executable mappings so
 * the ringbuf only carries EDR-relevant events. */
SEC("tp/syscalls/sys_enter_mmap")
int handle_image_load(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long prot;
    int fd;

    bpf_core_read(&prot, sizeof(prot), &ctx->args[2]);
    bpf_core_read(&fd,   sizeof(fd),   &ctx->args[4]);

    /* only executable mappings matter — this is the whole point of the module.
     * prot == 0 or prot without PROT_EXEC is data/heap/stack mmap, drop it. */
    if (!(prot & PROT_EXEC))
        return 0;

    struct ImageLoadEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    /* 10-field standard header (verbatim from Connect_Failed template) */
    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_IMAGE_LOAD;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* mmap syscall args: addr, len, prot, flags, fd, off */
    bpf_core_read(&e->imageLoadArguments.addr,  sizeof(e->imageLoadArguments.addr),  &ctx->args[0]);
    bpf_core_read(&e->imageLoadArguments.len,   sizeof(e->imageLoadArguments.len),   &ctx->args[1]);
    e->imageLoadArguments.prot = prot;
    bpf_core_read(&e->imageLoadArguments.flags, sizeof(e->imageLoadArguments.flags), &ctx->args[3]);
    e->imageLoadArguments.fd = fd;
    bpf_core_read(&e->imageLoadArguments.off,   sizeof(e->imageLoadArguments.off),   &ctx->args[5]);

    /* 差距 #3 stage 1: stash {len} — sys_exit_mmap registers the real base
     * (the request addr is usually a NULL hint). */
    {
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        struct mmap_pending mp = {.len = e->imageLoadArguments.len};
        bpf_map_update_elem(&mmap_args_map, &pid_tgid, &mp, BPF_ANY);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Phase 2 #2 Stage 2: mprotect(PROT_EXEC) — executable rights granted to an
 * already-existing mapping (RW->RWX on anonymous memory is the classic
 * shellcode/JIT pattern). Filter identical to mmap: no PROT_EXEC, no event. */
SEC("tp/syscalls/sys_enter_mprotect")
int handle_image_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long prot;

    bpf_core_read(&prot, sizeof(prot), &ctx->args[2]);
    if (!(prot & PROT_EXEC))
        return 0;

    struct ImageMprotectEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    /* 10-field standard header (same as handle_image_load) */
    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_IMAGE_MPROTECT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* mprotect syscall args: addr, len, prot */
    bpf_core_read(&e->imageMprotectArguments.addr, sizeof(e->imageMprotectArguments.addr), &ctx->args[0]);
    bpf_core_read(&e->imageMprotectArguments.len,  sizeof(e->imageMprotectArguments.len),  &ctx->args[1]);
    e->imageMprotectArguments.prot = prot;

    /* 差距 #3: mprotect addr is the live mapping address — register directly.
     * Value must go through a stack variable: &e->...len points into the
     * ringbuf record (PTR_TO_MEM) which the verifier rejects as a map-update
     * argument (host-verified fix, 2026-08-23). */
    unsigned long mlen = e->imageMprotectArguments.len;
    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    struct exec_map_key rk = {.tgid = tgid, .addr = e->imageMprotectArguments.addr};
    bpf_map_update_elem(&exec_maps, &rk, &mlen, BPF_ANY);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 差距 #3 stage 2: mmap retval is the actual mapping base — register it. */
SEC("tp/syscalls/sys_exit_mmap")
int handle_mmap_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct mmap_pending *mp = bpf_map_lookup_elem(&mmap_args_map, &pid_tgid);
    if (!mp)
        return 0;

    long ret = 0;
    bpf_core_read(&ret, sizeof(ret), &ctx->ret);
    bpf_map_delete_elem(&mmap_args_map, &pid_tgid);
    if (ret <= 0)                     /* mmap failed (negative errno) */
        return 0;

    struct exec_map_key rk = {.tgid = pid_tgid >> 32, .addr = (unsigned long)ret};
    bpf_map_update_elem(&exec_maps, &rk, &mp->len, BPF_ANY);
    return 0;
}

/* 差距 #3: report munmap of tracked executable mappings only (exact-key hit). */
SEC("tp/syscalls/sys_enter_munmap")
int handle_image_unload(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long addr, len;
    bpf_core_read(&addr, sizeof(addr), &ctx->args[0]);
    bpf_core_read(&len, sizeof(len), &ctx->args[1]);

    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    struct exec_map_key rk = {.tgid = tgid, .addr = addr};
    if (!bpf_map_lookup_elem(&exec_maps, &rk))
        return 0;

    struct ImageUnloadEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    /* 10-field standard header */
    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_IMAGE_UNLOAD;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->imageUnloadArguments.addr = addr;
    e->imageUnloadArguments.len = len;

    bpf_map_delete_elem(&exec_maps, &rk);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 差距 #3: kernel module load (rootkit surface). Name arrives as a __data_loc
 * dynamic string — same read pattern as sched_process_exec's filename. */
SEC("tp/module/module_load")
int handle_module_load(struct trace_event_raw_module_load *ctx)
{
    unsigned int taints;
    bpf_core_read(&taints, sizeof(taints), &ctx->taints);

    struct ImageModuleLoadEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    /* 10-field standard header */
    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_IMAGE_MODULE_LOAD;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    unsigned int name_off = ctx->__data_loc_name & 0xFFFF;
    bpf_probe_read_kernel_str(&e->imageModuleLoadArguments.name, sizeof(e->imageModuleLoadArguments.name), (void *)ctx + name_off);
    e->imageModuleLoadArguments.taints = taints;

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 差距 #3: kernel module unload (evasion surface). */
SEC("tp/module/module_free")
int handle_module_unload(struct trace_event_raw_module_free *ctx)
{
    struct ImageModuleUnloadEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    /* 10-field standard header */
    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_IMAGE_MODULE_UNLOAD;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    unsigned int name_off = ctx->__data_loc_name & 0xFFFF;
    bpf_probe_read_kernel_str(&e->imageModuleUnloadArguments.name, sizeof(e->imageModuleUnloadArguments.name), (void *)ctx + name_off);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
