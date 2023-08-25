// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../include/network.h"
#include "../../vmlinux.h"
#define AF_INET     2       /* Internet IP Protocol */
#define AF_INET6    10      /* IP version 6 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline __u16 my_ntohs(__u16 netshort) {
return ((netshort>>8)&0xff) | ((netshort<<8)&0xff00);
}

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024 * 1024);
} rb SEC(".maps");

struct accept_args {
    // ... 其他字段
    struct AcceptEvent event;
    u64 addrlen_ptr_value;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, struct accept_args);
} accept_args_map SEC(".maps");

struct accept4_args {
    // ... 其他字段
    struct Accept4Event event;
    u64 addrlen_ptr_value;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, struct accept_args);
} accept4_args_map SEC(".maps");

struct socketpair_args {
    struct SocketPairEvent event;
    u64 sv_value_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct socketpair_args);
} socketpair_args_map SEC(".maps");
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
SEC("tp/syscalls/sys_enter_accept")
int handle_socket_accept(struct trace_event_raw_sys_enter *ctx)
{
    struct AcceptEvent *e;
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
    e->event.event_type = EVENT_NETWORK_ACCEPT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->acceptArguments.fd, sizeof(e->acceptArguments.fd), &ctx->args[0]);
    int *addr_l_ptr = (int *)ctx->args[2];
    bpf_core_read(&e->acceptArguments.upper_addrlen, sizeof(e->acceptArguments.upper_addrlen), addr_l_ptr);

    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)ctx->args[1];
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->acceptArguments.sa_family = s_family;

    /* IPv4 */
    if (s_family == 2) {
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->acceptArguments.s_addr, sizeof(e->acceptArguments.s_addr), &sock->sin_addr.s_addr);
        __be16 s_port_network_order;
        bpf_core_read_user(&s_port_network_order, sizeof(s_port_network_order), &sock->sin_port);
        e->acceptArguments.s_port = s_port_network_order;  // Use ntohs function
    }
    /* IPv6 */
    else if (s_family == 10) {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->acceptArguments.s_addr_v6, sizeof(e->acceptArguments.s_addr_v6), &sock->sin6_addr);
        __be16 s_port_network_order;
        bpf_core_read_user(&s_port_network_order, sizeof(s_port_network_order), &sock->sin6_port);
        e->acceptArguments.s_port = s_port_network_order;  // Use ntohs function
    }

    // save data to map
    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args args = {};
    // 存储指针
    args.addrlen_ptr_value = (u64)ctx->args[2];
    args.event = *e;
    bpf_map_update_elem(&accept_args_map, &pid_tgid, &args, BPF_ANY);

    bpf_ringbuf_discard(e, 0);

    /* send data to user-space for post-processing */
    // bpf_ringbuf_submit(e, 0);
    // u32 pid_tgid = bpf_get_current_pid_tgid();
    // bpf_map_update_elem(&accept_tmp, &pid_tgid, &e, BPF_ANY);
    return 0;
}


SEC("tp/syscalls/sys_exit_accept")
int handle_socket_accept_exit(struct trace_event_raw_sys_exit *ctx) {

    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args *args;

    args = bpf_map_lookup_elem(&accept_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    if (ctx->ret >= 0) {
        int addrlen;
        struct AcceptEvent *e;
        bpf_probe_read_user(&addrlen, sizeof(addrlen), (void *)args->addrlen_ptr_value);
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
        {
            bpf_printk("buffer is overflowed, event is losing\n");
            return 0;
        }
        *e = args->event;
        bpf_core_read(&e->acceptArguments.upper_addrlen, sizeof(e->acceptArguments.upper_addrlen), &addrlen);
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&accept_args_map, &pid_tgid);
    return 0;
}
SEC("tp/syscalls/sys_enter_accept4")
int handle_socket_accept4(struct trace_event_raw_sys_enter *ctx)
{
    struct Accept4Event *e;
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
    e->event.event_type = EVENT_NETWORK_ACCEPT4;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->accept4Arguments.fd, sizeof(e->accept4Arguments.fd), &ctx->args[0]);
    int *addr_l_ptr = (int*)BPF_CORE_READ(ctx, args[2]);
    bpf_core_read(&e->accept4Arguments.upper_addrlen, sizeof(e->accept4Arguments.upper_addrlen), &addr_l_ptr[0]);
    bpf_core_read(&e->accept4Arguments.flags, sizeof(e->accept4Arguments.flags), &ctx->args[3]);
    
    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->accept4Arguments.sa_family = s_family;

    /* IPv4 */
    /* IPv4 */
    if (s_family == 2) {
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->accept4Arguments.s_addr, sizeof(e->accept4Arguments.s_addr), &sock->sin_addr.s_addr);
        __be16 s_port_network_order;
        bpf_core_read_user(&s_port_network_order, sizeof(s_port_network_order), &sock->sin_port);
        e->accept4Arguments.s_port = s_port_network_order;  // do not use ntohs function
    }
/* IPv6 */
    else if (s_family == 10) {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->accept4Arguments.s_addr_v6, sizeof(e->accept4Arguments.s_addr_v6), &sock->sin6_addr);
        __be16 s_port_network_order;
        bpf_core_read_user(&s_port_network_order, sizeof(s_port_network_order), &sock->sin6_port);
        e->accept4Arguments.s_port = s_port_network_order;  // do not use ntohs function
    }

    // save data to map
    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct accept4_args args = {};
    // 存储指针
    args.addrlen_ptr_value = (u64)ctx->args[2];
    args.event = *e;
    bpf_map_update_elem(&accept4_args_map, &pid_tgid, &args, BPF_ANY);

    bpf_ringbuf_discard(e, 0);

    /* send data to user-space for post-processing */
    // bpf_ringbuf_submit(e, 0);
    // u32 pid_tgid = bpf_get_current_pid_tgid();
    // bpf_map_update_elem(&accept_tmp, &pid_tgid, &e, BPF_ANY);
    return 0;
}
SEC("tp/syscalls/sys_exit_accept4")
int handle_socket_accept4_exit(struct trace_event_raw_sys_exit *ctx) {

    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct accept4_args *args;

    args = bpf_map_lookup_elem(&accept4_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    if (ctx->ret >= 0) {
        int addrlen;
        struct Accept4Event *e;
        bpf_probe_read_user(&addrlen, sizeof(addrlen), (void *)args->addrlen_ptr_value);
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
        {
            bpf_printk("buffer is overflowed, event is losing\n");
            return 0;
        }
        *e = args->event;
        bpf_core_read(&e->accept4Arguments.upper_addrlen, sizeof(e->accept4Arguments.upper_addrlen), &addrlen);
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&accept_args_map, &pid_tgid);
    return 0;
}
SEC("tp/syscalls/sys_enter_bind")
int handle_socket_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct BindEvent *e;
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
    e->event.event_type = EVENT_NETWORK_BIND;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->bindArguments.fd, sizeof(e->bindArguments.fd), &ctx->args[0]);
    bpf_core_read(&e->bindArguments.addrlen, sizeof(e->bindArguments.addrlen), &ctx->args[2]);

    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->bindArguments.sa_family = s_family;
    
    /* IPv4 */
    if (s_family == 2)
    {
        // bpf_printk("charo!\n");
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->bindArguments.s_addr, sizeof(e->bindArguments.s_addr), &sock->sin_addr.s_addr);
        bpf_core_read_user(&e->bindArguments.s_port, sizeof(e->bindArguments.s_port), &sock->sin_port);
    }
    /* IPv6 */
    else if (s_family == 10)
    {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->bindArguments.s_addr_v6, sizeof(e->bindArguments.s_addr_v6), &sock->sin6_addr);
        bpf_core_read_user(&e->bindArguments.s_port, sizeof(e->bindArguments.s_port), &sock->sin6_port);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_getpeername")
int handle_socket_getpeername(struct trace_event_raw_sys_enter *ctx)
{
    //bpf_trace_printk(">>>>>>>>>>>>>>>>:%d\n",1000);
    struct GetPeerNameEvent *e;
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
    e->event.event_type = EVENT_NETWORK_GETPEERNAME;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->getpeernameArguments.fd, sizeof(e->getpeernameArguments.fd), &ctx->args[0]);
    //bpf_core_read(&e->getpeernameArguments.addr_len, sizeof(e->getpeernameArguments.addr_len), &ctx->args[2]);
    int *addr_l_ptr = (int*)BPF_CORE_READ(ctx, args[2]);
    bpf_core_read_user(&e->getpeernameArguments.addr_len, sizeof(e->getpeernameArguments.addr_len), addr_l_ptr);
    /* retrieve address family for subsequent processing */
    struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);
    unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    e->getpeernameArguments.sa_family = s_family;
    
    /* IPv4 */
    if (s_family == 2)
    {
        // bpf_printk("charo!\n");
        struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->getpeernameArguments.s_addr, sizeof(e->getpeernameArguments.s_addr), &sock->sin_addr.s_addr);
        bpf_core_read_user(&e->getpeernameArguments.s_port, sizeof(e->getpeernameArguments.s_port), &sock->sin_port);
    }
    /* IPv6 */
    else if (s_family == 10)
    {
        struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ(ctx, args[1]);
        bpf_core_read_user(&e->getpeernameArguments.s_addr_v6, sizeof(e->getpeernameArguments.s_addr_v6), &sock->sin6_addr);
        bpf_core_read_user(&e->getpeernameArguments.s_port, sizeof(e->getpeernameArguments.s_port), &sock->sin6_port);
    }

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_recvmmsg")
int handle_recvmmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct RecvMmsgEvent *e;
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
    e->event.event_type = EVENT_NETWORK_RECVMMSG;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->recvmmsgArguments.fd, sizeof(e->recvmmsgArguments.fd), &ctx->args[0]);
    //struct user_msghdr *msg = (struct user_msghdr *)BPF_CORE_READ(ctx, args[1]);
    bpf_core_read(&e->recvmmsgArguments.flags, sizeof(e->recvmmsgArguments.flags), &ctx->args[3]);
    bpf_core_read(&e->recvmmsgArguments.vlen, sizeof(e->recvmmsgArguments.vlen), &ctx->args[2]);
    //bpf_core_read_user(&e->recvmmsgArguments.addr_len, sizeof(e->recvmmsgArguments.addr_len), &msg->msg_namelen);
    //bpf_core_read_user(&e->recvmmsgArguments.mmsg_flags, sizeof(e->recvmmsgArguments.mmsg_flags), &msg->msg_flags);

    /* retrieve address family for subsequent processing */
  
    //struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ_USER(msg, msg_name);
    //unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    //e->recvmmsgArguments.sa_family = s_family;

    /* IPv4 */
    //if (s_family == 2)
    //{
        //struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ_USER(msg, msg_name);
        //bpf_core_read_user(&e->recvmmsgArguments.s_addr, sizeof(e->recvmmsgArguments.s_addr), &sock->sin_addr.s_addr);
        //bpf_core_read_user(&e->recvmmsgArguments.s_port, sizeof(e->recvmmsgArguments.s_port), &sock->sin_port);
    //}
    /* IPv6 */
    //else if (s_family == 10)
    //{
        //struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ_USER(msg, msg_name);
        //bpf_core_read_user(&e->recvmmsgArguments.s_addr_v6, sizeof(e->recvmmsgArguments.s_addr_v6), &sock->sin6_addr);
        //bpf_core_read_user(&e->recvmmsgArguments.s_port, sizeof(e->recvmmsgArguments.s_port), &sock->sin6_port);
    //}

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_sendmmsg")
int handle_sendmmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct SendMmsgEvent *e;
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
    e->event.event_type = EVENT_NETWORK_SENDMMSG;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->sendmmsgArguments.fd, sizeof(e->sendmmsgArguments.fd), &ctx->args[0]);
    //struct user_msghdr *msg = (struct user_msghdr *)BPF_CORE_READ(ctx, args[1]);
    bpf_core_read(&e->sendmmsgArguments.flags, sizeof(e->sendmmsgArguments.flags), &ctx->args[3]);
    bpf_core_read(&e->sendmmsgArguments.vlen, sizeof(e->sendmmsgArguments.vlen), &ctx->args[2]);
    //bpf_core_read_user(&e->sendmmsgArguments.addr_len, sizeof(e->sendmmsgArguments.addr_len), &msg->msg_namelen);
    //bpf_core_read_user(&e->sendmmsgArguments.mmsg_flags, sizeof(e->sendmmsgArguments.mmsg_flags), &msg->msg_flags);

    /* retrieve address family for subsequent processing */
  
    //struct sockaddr *sock_addr = (struct sockaddr *)BPF_CORE_READ_USER(msg, msg_name);
    //unsigned short s_family = BPF_CORE_READ_USER(sock_addr, sa_family);
    //e->sendmmsgArguments.sa_family = s_family;

    /* IPv4 */
    //if (s_family == 2)
    //{
        //struct sockaddr_in *sock = (struct sockaddr_in *)BPF_CORE_READ_USER(msg, msg_name);
        //bpf_core_read_user(&e->sendmmsgArguments.s_addr, sizeof(e->sendmmsgArguments.s_addr), &sock->sin_addr.s_addr);
        //bpf_core_read_user(&e->sendmmsgArguments.s_port, sizeof(e->sendmmsgArguments.s_port), &sock->sin_port);
    //}
    /* IPv6 */
    //else if (s_family == 10)
    //{
        //struct sockaddr_in6 *sock = (struct sockaddr_in6 *)BPF_CORE_READ_USER(msg, msg_name);
        //bpf_core_read_user(&e->sendmmsgArguments.s_addr_v6, sizeof(e->sendmmsgArguments.s_addr_v6), &sock->sin6_addr);
        //bpf_core_read_user(&e->sendmmsgArguments.s_port, sizeof(e->sendmmsgArguments.s_port), &sock->sin6_port);
    //}

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("tp/syscalls/sys_enter_socketpair")
int handle_socket_socketpair_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct SocketPairEvent *e;
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
    e->event.event_type = EVENT_NETWORK_SOCKETPAIR;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->socketpairArguments.family, sizeof(e->socketpairArguments.family), &ctx->args[0]);
    bpf_core_read(&e->socketpairArguments.type, sizeof(e->socketpairArguments.type), &ctx->args[1]);
    bpf_core_read(&e->socketpairArguments.protocol, sizeof(e->socketpairArguments.protocol), &ctx->args[2]);
    int *addr_l_ptr = (int*)BPF_CORE_READ(ctx, args[3]);
    //bpf_core_read_user(&e->socketpairArguments.sv1, sizeof(e->socketpairArguments.sv1), &addr_l_ptr[0]);
    //bpf_core_read_user(&e->socketpairArguments.sv2, sizeof(e->socketpairArguments.sv2), &addr_l_ptr[1]);

    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct socketpair_args args = {};
    args.sv_value_ptr = (u64)addr_l_ptr;
    args.event = *e;
    bpf_map_update_elem(&socketpair_args_map, &pid_tgid, &args, BPF_ANY);

    /* send data to user-space for post-processing */
    bpf_ringbuf_discard(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_socketpair")
int handle_socket_socketpair_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid_tgid = bpf_get_current_pid_tgid();
    struct socketpair_args *args;

    args = bpf_map_lookup_elem(&socketpair_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }

    if (ctx->ret >= 0){
        int sv[2]; // array to hold sv values
        if (bpf_probe_read_user(&sv, sizeof(sv), (void *)args->sv_value_ptr) == 0) {
            struct SocketPairEvent *e;
            e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if(!e){
                bpf_printk("buffer is overflowed, event is losing\n");
                return 0;
            }
            *e = args->event;
            e->socketpairArguments.sv1 = sv[0];
            e->socketpairArguments.sv2 = sv[1];
            bpf_ringbuf_submit(e, 0);
        }
    }
    bpf_map_delete_elem(&socketpair_args_map, &pid_tgid);
    return 0;
}
