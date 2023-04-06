// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../include/network.h"
#include "../../vmlinux.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_connect")
int handle_socket_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct ConnectEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_NETWORK_CONNECT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->connectArguments.fd, sizeof(e->connectArguments.fd), &ctx->args[0]);
    bpf_core_read(&e->connectArguments.addrlen, sizeof(e->connectArguments.addrlen), &ctx->args[2]);

    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->connectArguments.sa_family = s_family;
    
    /* IPv4 */
    if (s_family == 2)
    {
        // bpf_printk("charo!\n");
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->connectArguments.s_addr, sizeof(e->connectArguments.s_addr), &sock->sin_addr.s_addr);
        bpf_core_read_user(&e->connectArguments.s_port, sizeof(e->connectArguments.s_port), &sock->sin_port);
    }
    /* IPv6 */
    else if (s_family == 10)
    {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->connectArguments.s_addr_v6, sizeof(e->connectArguments.s_addr_v6), &sock->sin6_addr);
        bpf_core_read_user(&e->connectArguments.s_port, sizeof(e->connectArguments.s_port), &sock->sin6_port);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct SendEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_NETWORK_SENDTO;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->sendArguments.fd, sizeof(e->sendArguments.fd), &ctx->args[0]);
    // TODO: How to get buffer content at args[1]?
    bpf_core_read(&e->sendArguments.len, sizeof(e->sendArguments.len), &ctx->args[2]);
    bpf_core_read(&e->sendArguments.flags, sizeof(e->sendArguments.flags), &ctx->args[3]);
    bpf_core_read(&e->sendArguments.addr_len, sizeof(e->sendArguments.addr_len), &ctx->args[5]);
    
    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[4]);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->sendArguments.sa_family = s_family;

    /* IPv4 */
    if (s_family == 2)
    {
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[4]);
        bpf_core_read_user(&e->sendArguments.s_addr, sizeof(e->sendArguments.s_addr), &sock->sin_addr.s_addr);
        bpf_core_read_user(&e->sendArguments.s_port, sizeof(e->sendArguments.s_port), &sock->sin_port);
    }
    /* IPv6 */
    else if (s_family == 10)
    {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[4]);
        bpf_core_read_user(&e->sendArguments.s_addr_v6, sizeof(e->sendArguments.s_addr_v6), &sock->sin6_addr);
        bpf_core_read_user(&e->sendArguments.s_port, sizeof(e->sendArguments.s_port), &sock->sin6_port);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int handle_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    struct RecvEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_NETWORK_RECVFROM;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->recvArguments.fd, sizeof(e->recvArguments.fd), &ctx->args[0]);
    bpf_core_read(&e->recvArguments.len, sizeof(e->recvArguments.len), &ctx->args[2]);
    bpf_core_read(&e->recvArguments.flags, sizeof(e->recvArguments.flags), &ctx->args[3]);
    int *addr_l_ptr = (int*)BPF_CORE_READ(ctx, args[5]);
    bpf_core_read(&e->recvArguments.addr_len, sizeof(e->recvArguments.addr_len), addr_l_ptr);
    
    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[4]);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->recvArguments.sa_family = s_family;

    /* IPv4 */
    if (s_family == 2)
    {
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[4]);
        bpf_core_read_user(&e->recvArguments.s_addr, sizeof(e->recvArguments.s_addr), &sock->sin_addr.s_addr);
        bpf_core_read_user(&e->recvArguments.s_port, sizeof(e->recvArguments.s_port), &sock->sin_port);
    }
    /* IPv6 */
    else if (s_family == 10)
    {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[4]);
        bpf_core_read_user(&e->recvArguments.s_addr_v6, sizeof(e->recvArguments.s_addr_v6), &sock->sin6_addr);
        bpf_core_read_user(&e->recvArguments.s_port, sizeof(e->recvArguments.s_port), &sock->sin6_port);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_sendmsg")
int handle_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct SendRecvMsgEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_NETWORK_SENDMSG;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->sendRecvMsgArguments.fd, sizeof(e->sendRecvMsgArguments.fd), &ctx->args[0]);
    struct user_msghdr *msg = (struct user_msghdr *)BPF_CORE_READ(ctx, args[1]);
    bpf_core_read(&e->sendRecvMsgArguments.flags, sizeof(e->sendRecvMsgArguments.flags), &ctx->args[2]);

    bpf_core_read_user(&e->sendRecvMsgArguments.addr_len, sizeof(e->sendRecvMsgArguments.addr_len), &msg->msg_namelen);
    bpf_core_read_user(&e->sendRecvMsgArguments.msg_flags, sizeof(e->sendRecvMsgArguments.msg_flags), &msg->msg_flags);

    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ_USER(msg, msg_name);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->sendRecvMsgArguments.sa_family = s_family;

    /* IPv4 */
    if (s_family == 2)
    {
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ_USER(msg, msg_name);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_addr, sizeof(e->sendRecvMsgArguments.s_addr), &sock->sin_addr.s_addr);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_port, sizeof(e->sendRecvMsgArguments.s_port), &sock->sin_port);
    }
    /* IPv6 */
    else if (s_family == 10)
    {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ_USER(msg, msg_name);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_addr_v6, sizeof(e->sendRecvMsgArguments.s_addr_v6), &sock->sin6_addr);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_port, sizeof(e->sendRecvMsgArguments.s_port), &sock->sin6_port);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_recvmsg")
int handle_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct SendRecvMsgEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_NETWORK_RECVMSG;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->sendRecvMsgArguments.fd, sizeof(e->sendRecvMsgArguments.fd), &ctx->args[0]);
    struct user_msghdr *msg = (struct user_msghdr *)BPF_CORE_READ(ctx, args[1]);
    bpf_core_read(&e->sendRecvMsgArguments.flags, sizeof(e->sendRecvMsgArguments.flags), &ctx->args[2]);

    bpf_core_read_user(&e->sendRecvMsgArguments.addr_len, sizeof(e->sendRecvMsgArguments.addr_len), &msg->msg_namelen);
    bpf_core_read_user(&e->sendRecvMsgArguments.msg_flags, sizeof(e->sendRecvMsgArguments.msg_flags), &msg->msg_flags);

    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ_USER(msg, msg_name);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->sendRecvMsgArguments.sa_family = s_family;

    /* IPv4 */
    if (s_family == 2)
    {
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ_USER(msg, msg_name);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_addr, sizeof(e->sendRecvMsgArguments.s_addr), &sock->sin_addr.s_addr);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_port, sizeof(e->sendRecvMsgArguments.s_port), &sock->sin_port);
    }
    /* IPv6 */
    else if (s_family == 10)
    {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ_USER(msg, msg_name);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_addr_v6, sizeof(e->sendRecvMsgArguments.s_addr_v6), &sock->sin6_addr);
        bpf_core_read_user(&e->sendRecvMsgArguments.s_port, sizeof(e->sendRecvMsgArguments.s_port), &sock->sin6_port);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
