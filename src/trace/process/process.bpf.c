#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../include/process.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024 * 1024);
} rb SEC(".maps");

// SEC("tp/sched/sched_process_fork")
// int handle_fork(struct ForkArguments *ctx)
// {
//     struct ForkEvent *e;
//     struct task_struct *task;

//     e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//     if(!e){
//         bpf_printk("buffer is overflowed, event is losing\n");
//         return 0;
//     }

//     task = (struct task_struct *)bpf_get_current_task();

//     e->event.pid = BPF_CORE_READ(task, pid);
//     e->event.ppid = BPF_CORE_READ(task, tgid);
//     e->event.event_type = EVENT_PROCESS_FORK;
//     e->event.is_process = e->event.pid == e->event.ppid;

//     e->event.user_mode_time = BPF_CORE_READ(task, utime);
//     e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
//     e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
//     e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
//     e->event.start_time = BPF_CORE_READ(task, start_time);

//     e->forkArguments.parent_pid = ctx->parent_pid;
//     e->forkArguments.child_pid = ctx->child_pid;
// 	bpf_probe_read_str(&e->forkArguments.parent_comm, sizeof(e->forkArguments.parent_comm), &ctx->parent_comm);
// 	bpf_probe_read_str(&e->forkArguments.child_comm, sizeof(e->forkArguments.child_comm), &ctx->child_comm);

//     bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

//     /* send data to user-space for post-processing */
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tp/sched/sched_process_exec")
// int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
// {
//     struct ExecEvent *e;
//     struct task_struct *task;

//     e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//     if(!e){
//         bpf_printk("buffer is overflowed, event is losing\n");
//         return 0;
//     }

//     task = (struct task_struct *)bpf_get_current_task();

//     e->event.pid = BPF_CORE_READ(task, pid);
//     e->event.ppid = BPF_CORE_READ(task, tgid);
//     e->event.event_type = EVENT_PROCESS_EXEC;
//     e->event.is_process = e->event.pid == e->event.ppid;

//     e->event.user_mode_time = BPF_CORE_READ(task, utime);
//     e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
//     e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
//     e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
//     e->event.start_time = BPF_CORE_READ(task, start_time);

//     unsigned fname_off;
//     fname_off = ctx->__data_loc_filename & 0xFFFF;
//     bpf_probe_read_str(&e->event.filename, sizeof(e->event.filename), (void *)ctx + fname_off);

//     bpf_core_read(&e->execArguments.pid, sizeof(e->execArguments.pid), &ctx->pid);
//     bpf_core_read(&e->execArguments.old_pid, sizeof(e->execArguments.old_pid), &ctx->old_pid);

//     bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

//     /* send data to user-space for post-processing */
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tp/syscalls/sys_enter_clone")
// int handle_clone(struct trace_event_raw_sys_enter *ctx)
// {
//     struct CloneEvent *e;
//     struct task_struct *task;
//     e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
//     if(!e){
//         bpf_printk("buffer is overflowed, event is losing\n");
//         return 0;
//     }

//     task = (struct task_struct *)bpf_get_current_task();

//     e->event.pid = BPF_CORE_READ(task, pid);
//     e->event.ppid = BPF_CORE_READ(task, tgid);
//     e->event.event_type = EVENT_PROCESS_CLONE;
//     e->event.is_process = e->event.pid == e->event.ppid;

//     e->event.user_mode_time = BPF_CORE_READ(task, utime);
//     e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
//     e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
//     e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
//     e->event.start_time = BPF_CORE_READ(task, start_time);

//     bpf_core_read(&e->cloneArguments.clone_flags, sizeof(e->cloneArguments.clone_flags), &ctx->args[0]);
//     bpf_core_read(&e->cloneArguments.newsp, sizeof(e->cloneArguments.newsp), &ctx->args[1]);
//     bpf_core_read(&e->cloneArguments.parent_tidptr, sizeof(e->cloneArguments.parent_tidptr), &ctx->args[2]);
//     bpf_core_read(&e->cloneArguments.child_tidptr, sizeof(e->cloneArguments.child_tidptr), &ctx->args[3]);
//     bpf_core_read(&e->cloneArguments.tls, sizeof(e->cloneArguments.tls), &ctx->args[4]);

//     bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

//     /* send data to user-space for post-processing */
//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }

// SEC("tp/syscalls/sys_enter_exit_group")
// int handle_sys_exit(struct trace_event_raw_sys_enter *ctx)
SEC("tp/sched/sched_process_exit")
int handle_sys_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct ExitEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_EXIT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    // bpf_core_read(&e->exitArguments.prio, sizeof(e->exitArguments.prio), &ctx->args[0]);
    bpf_core_read(&e->exitArguments.pid, sizeof(e->exitArguments.pid), &ctx->pid);
    bpf_core_read_str(&e->exitArguments.comm, sizeof(e->exitArguments.comm), &ctx->comm);
    bpf_core_read(&e->exitArguments.prio, sizeof(e->exitArguments.prio), &ctx->prio);
    e->exitArguments.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
