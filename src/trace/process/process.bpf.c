// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../include/process.h"

#define BPF_MAX_STACK_DEPTH 128

char LICENSE[] SEC("license") = "Dual BSD/GPL";
static __always_inline __u16 my_ntohs(__u16 netshort) {
return ((netshort>>8)&0xff) | ((netshort<<8)&0xff00);
}
struct pipe_args {
    struct PipeEvent event;
    u64 sv_value_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct pipe_args);
} pipe_args_map SEC(".maps");
struct pipe2_args {
    struct Pipe2Event event;
    u64 sv_value_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct pipe2_args);
} pipe2_args_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_fork")
int handle_fork(struct ForkArguments *ctx)
{
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
    e->event.event_type = EVENT_PROCESS_FORK;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    e->forkArguments.parent_pid = ctx->parent_pid;
    e->forkArguments.child_pid = ctx->child_pid;
	bpf_probe_read_str(&e->forkArguments.parent_comm, sizeof(e->forkArguments.parent_comm), &ctx->parent_comm);
	bpf_probe_read_str(&e->forkArguments.child_comm, sizeof(e->forkArguments.child_comm), &ctx->child_comm);

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
    e->event.event_type = EVENT_PROCESS_EXEC;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    unsigned fname_off;
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->event.filename, sizeof(e->event.filename), (void *)ctx + fname_off);

    bpf_core_read(&e->execArguments.pid, sizeof(e->execArguments.pid), &ctx->pid);
    bpf_core_read(&e->execArguments.old_pid, sizeof(e->execArguments.old_pid), &ctx->old_pid);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));
    __u64 stack[BPF_MAX_STACK_DEPTH/4] = {};
    int stack_depth = bpf_get_stack(ctx, &stack, BPF_MAX_STACK_DEPTH, 0);
    bpf_printk("stack[%d]: \n", stack_depth/8);
bpf_printk("stack[%d]: 0x%llx\n", 0, stack[0]);
    bpf_printk("stack[%d]: 0x%llx\n", 1, stack[1]);
    bpf_printk("stack[%d]: 0x%llx\n", 2, stack[2]);
    bpf_printk("stack[%d]: 0x%llx\n", 3, stack[3]);
    char func_name[64]; // 假设函数名不超过 64 个字符
char fmt[] = "Function name: %s\n";
int len = 0;

len = bpf_probe_read_kernel_str(func_name, sizeof(func_name), (void *)stack[0]); // 从内核地址读取函数名
    if (len > 0) {
    func_name[len] = '\0';  // 确保字符串以 null 结尾
    bpf_trace_printk(fmt, sizeof(fmt), func_name); // 打印函数名
} else {
    bpf_trace_printk(fmt, sizeof(fmt), "Failed to read function name\n"); // 如果读取失败，打印错误信息
}
len = bpf_probe_read_kernel_str(func_name, sizeof(func_name), (void *)stack[1]); // 从内核地址读取函数名
if (len > 0) {
    func_name[len] = '\0';  // 确保字符串以 null 结尾
    bpf_trace_printk(fmt, sizeof(fmt), func_name); // 打印函数名
} else {
    bpf_trace_printk(fmt, sizeof(fmt), "Failed to read function name\n"); // 如果读取失败，打印错误信息
}
    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx)
{
    struct CloneEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_CLONE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_core_read(&e->cloneArguments.clone_flags, sizeof(e->cloneArguments.clone_flags), &ctx->args[0]);
    bpf_core_read(&e->cloneArguments.newsp, sizeof(e->cloneArguments.newsp), &ctx->args[1]);
    bpf_core_read(&e->cloneArguments.parent_tidptr, sizeof(e->cloneArguments.parent_tidptr), &ctx->args[2]);
    bpf_core_read(&e->cloneArguments.child_tidptr, sizeof(e->cloneArguments.child_tidptr), &ctx->args[3]);
    bpf_core_read(&e->cloneArguments.tls, sizeof(e->cloneArguments.tls), &ctx->args[4]);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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
SEC("tp/syscalls/sys_enter_pipe")
int handle_pipe(struct trace_event_raw_sys_enter *ctx)
{
    struct PipeEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_PIPE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    int *array = (int*)BPF_CORE_READ(ctx, args[0]);


    bpf_core_read(&e->pipeArguments.f1,sizeof(int),&array[0]);
    bpf_core_read(&e->pipeArguments.f2,sizeof(int),&array[1]);


    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct pipe_args args = {};
    args.sv_value_ptr = (u64)array;
    args.event = *e;
    bpf_map_update_elem(&pipe_args_map, &pid_tgid, &args, BPF_ANY);

    /* send data to user-space for post-processing */
    bpf_ringbuf_discard(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_exit_pipe")
int handle_socket_pipe_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct pipe_args *args;

    args = bpf_map_lookup_elem(&pipe_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    if (ctx->ret >= 0){
        int sv[2]; // array to hold sv values
        if (bpf_probe_read_user(&sv, sizeof(sv), (void *)args->sv_value_ptr) == 0) {
            struct PipeEvent *e;
            e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if(!e){
                bpf_printk("buffer is overflowed, event is losing\n");
                return 0;
            }
            *e = args->event;
            e->pipeArguments.f1 = sv[0];
            e->pipeArguments.f2 = sv[1];
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&pipe_args_map, &pid_tgid);
    return 0;
}
SEC("tp/syscalls/sys_enter_pipe2")
int handle_pipe2(struct trace_event_raw_sys_enter *ctx)
{
    struct Pipe2Event *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_PIPE2;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
        int *array = (int*)BPF_CORE_READ(ctx, args[0]);


    bpf_core_read(&e->pipe2Arguments.f1,sizeof(int),&array[0]);
    bpf_core_read(&e->pipe2Arguments.f2,sizeof(int),&array[1]);

    bpf_core_read(&e->pipe2Arguments.flags, sizeof(e->pipe2Arguments.flags), &ctx->args[1]);


    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct pipe2_args args = {};
    args.sv_value_ptr = (u64)array;
    args.event = *e;
    bpf_map_update_elem(&pipe2_args_map, &pid_tgid, &args, BPF_ANY);

    /* send data to user-space for post-processing */
    bpf_ringbuf_discard(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_exit_pipe2")
int handle_socket_pipe2_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct pipe2_args *args;

    args = bpf_map_lookup_elem(&pipe2_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    if (ctx->ret >= 0){
        int sv[2]; // array to hold sv values
        if (bpf_probe_read_user(&sv, sizeof(sv), (void *)args->sv_value_ptr) == 0) {
            struct Pipe2Event *e;
            e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if(!e){
                bpf_printk("buffer is overflowed, event is losing\n");
                return 0;
            }
            *e = args->event;
            e->pipe2Arguments.f1 = sv[0];
            e->pipe2Arguments.f2 = sv[1];
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&pipe2_args_map, &pid_tgid);
    return 0;
}
SEC("tp/syscalls/sys_enter_kill")
int handle_kill(struct trace_event_raw_sys_enter *ctx)
{
    struct KillEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_KILL;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_core_read(&e->killArguments.pid, sizeof(e->killArguments.pid), &ctx->args[0]);
    bpf_core_read(&e->killArguments.sig, sizeof(e->killArguments.sig), &ctx->args[1]);


    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_clone3")
int handle_clone3(struct trace_event_raw_sys_enter *ctx)
{
    struct Clone3Event *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_CLONE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    //struct clone_args *uargs = (struct clone_args *)BPF_CORE_READ(ctx, args[0]);
    //unsigned long flags = BPF_CORE_READ_USER(uargs, flags);
    //int * child_tid=BPF_CORE_READ_USER(uargs, child_tid);
    //int * parent_tid=BPF_CORE_READ_USER(uargs, parent_tid);
    //e->clone3Arguments.clone_flags = flags;
    //e->clone3Arguments.parent_tidptr = parent_tid;
    //e->clone3Arguments.child_tidptr = child_tid;
    bpf_core_read(&e->clone3Arguments.size, sizeof(e->clone3Arguments.size), &ctx->args[1]);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct ExecveEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_EXECVE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    
    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->execveArguments.filename, sizeof(e->execveArguments.filename), filename_ptr);


    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct ExecveatEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_EXECVEAT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    
    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->execveatArguments.filename, sizeof(e->execveatArguments.filename), filename_ptr);
    bpf_core_read(&e->execveatArguments.fd, sizeof(e->execveatArguments.fd), &ctx->args[0]);
    bpf_core_read(&e->execveatArguments.flags, sizeof(e->execveatArguments.flags), &ctx->args[4]);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_exit_group")
int handle_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    struct Exit_groupEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_EXIT_GROUP;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    

    bpf_core_read(&e->exitgroupArguments.exit_code, sizeof(e->exitgroupArguments.exit_code), &ctx->args[0]);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct PtraceEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_PTRACE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    

    bpf_core_read(&e->ptraceArguments.request, sizeof(e->ptraceArguments.request), &ctx->args[0]);
    bpf_core_read(&e->ptraceArguments.pid, sizeof(e->ptraceArguments.pid), &ctx->args[1]);
    bpf_core_read(&e->ptraceArguments.addr, sizeof(e->ptraceArguments.addr), &ctx->args[2]);
    bpf_core_read(&e->ptraceArguments.data, sizeof(e->ptraceArguments.data), &ctx->args[3]);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_tgkill")
int handle_tgkill(struct trace_event_raw_sys_enter *ctx)
{
    struct TgkillEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_TGKILL;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_core_read(&e->tgkillArguments.tgid, sizeof(e->tgkillArguments.tgid), &ctx->args[0]);
    bpf_core_read(&e->tgkillArguments.pid, sizeof(e->tgkillArguments.pid), &ctx->args[1]);
    bpf_core_read(&e->tgkillArguments.sig, sizeof(e->tgkillArguments.sig), &ctx->args[2]);


    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_tkill")
int handle_tkill(struct trace_event_raw_sys_enter *ctx)
{
    struct TkillEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_TKILL;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_core_read(&e->tkillArguments.pid, sizeof(e->tkillArguments.pid), &ctx->args[0]);
    bpf_core_read(&e->tkillArguments.sig, sizeof(e->tkillArguments.sig), &ctx->args[1]);


    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_vfork")
int handle_vfork(struct trace_event_raw_sys_enter *ctx)
{
    struct VforkEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_VFORK;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);



    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx)
{
    struct MmapEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_MMAP;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    

    bpf_core_read(&e->mmapArguments.addr, sizeof(e->mmapArguments.addr), &ctx->args[0]);
    bpf_core_read(&e->mmapArguments.len, sizeof(e->mmapArguments.len), &ctx->args[1]);
    bpf_core_read(&e->mmapArguments.prot, sizeof(e->mmapArguments.prot), &ctx->args[2]);
    bpf_core_read(&e->mmapArguments.flags, sizeof(e->mmapArguments.flags), &ctx->args[3]);
    bpf_core_read(&e->mmapArguments.fd, sizeof(e->mmapArguments.fd), &ctx->args[4]);
    bpf_core_read(&e->mmapArguments.off, sizeof(e->mmapArguments.off), &ctx->args[5]);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_mprotect")
int handle_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    struct MprotectEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_PROCESS_MPROTECT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);
    

    bpf_core_read(&e->mprotectArguments.start, sizeof(e->mprotectArguments.start), &ctx->args[0]);
    bpf_core_read(&e->mprotectArguments.len, sizeof(e->mprotectArguments.len), &ctx->args[1]);
    bpf_core_read(&e->mprotectArguments.prot, sizeof(e->mprotectArguments.prot), &ctx->args[2]);


    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
