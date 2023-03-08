//
// Created by zhuzhiling on 9/7/22.
//

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../../include/demo.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_fork")
//SEC("tp/syscalls/sys_enter_clone")
int handle_fork(struct CloneArguments *ctx)
{
    //struct CloneArguments *ca = (struct CloneArguments*)ctx;
    struct ForkEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FORK;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    //int temp = *BPF_CORE_READ(ca, parent_tidptr);
    //bpf_core_read(temp, sizeof(temp), ca->parent_tidptr);

    //e->a = *BPF_CORE_READ(ca, parent_tidptr);
    //e->b = temp;
    //bpf_printk("fork ================ parent comm %s \n", BPF_CORE_READ(ctx, parent_comm));

//    e->uid = BPF_CORE_READ(task, cred, uid);
//    e->gid = BPF_CORE_READ(task, cred, gid);
//    e->euid = BPF_CORE_READ(task, cred, euid);
//    e->egid = BPF_CORE_READ(task, cred, egid);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct ExecEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_EXEC;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    unsigned fname_off;
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->event.filename, sizeof(e->event.filename), (void *)ctx + fname_off);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exec *ctx)
{
    struct Event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = BPF_CORE_READ(task, pid);
    e->ppid = BPF_CORE_READ(task, tgid);
    e->event_type = EVENT_EXIT;
    e->is_process = e->pid == e->ppid;

    e->user_mode_time = BPF_CORE_READ(task, utime);
    e->kernel_mode_time = BPF_CORE_READ(task, stime);
    e->voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tp/syscalls/sys_enter_openat")
int handle_open(void *ctx)
{
    struct OpenEvent *e;
    struct task_struct *task;
    struct OpenArguments *oa = (struct OpenArguments*)ctx;

    bpf_printk("ctx contains %-16d \n", oa->flags);

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_OPEN;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);


    //e->openArguments.common_pid = BPF_CORE_READ(oa, common_pid);
    //e->openArguments.filename = oa->filename;

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry, struct file *file, char *buf, size_t count, loff_t *pos)
{

    bpf_printk("123");
    return 0;
}


SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sched_process_exec *ctx)
{
    struct Event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = BPF_CORE_READ(task, pid);
    e->ppid = BPF_CORE_READ(task, tgid);
    e->event_type = EVENT_CLOSE;
    e->is_process = e->pid == e->ppid;

    e->user_mode_time = BPF_CORE_READ(task, utime);
    e->kernel_mode_time = BPF_CORE_READ(task, stime);
    e->voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}



SEC("tp/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sched_process_exec *ctx)
{
    struct Event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = BPF_CORE_READ(task, pid);
    e->ppid = BPF_CORE_READ(task, tgid);
    e->event_type = EVENT_READ;
    e->is_process = e->pid == e->ppid;

    e->user_mode_time = BPF_CORE_READ(task, utime);
    e->kernel_mode_time = BPF_CORE_READ(task, stime);
    e->voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sched_process_exec *ctx)
{
    struct Event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = BPF_CORE_READ(task, pid);
    e->ppid = BPF_CORE_READ(task, tgid);
    e->event_type = EVENT_WRITE;
    e->is_process = e->pid == e->ppid;

    e->user_mode_time = BPF_CORE_READ(task, utime);
    e->kernel_mode_time = BPF_CORE_READ(task, stime);
    e->voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
