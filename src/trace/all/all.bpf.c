// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Created by zhuzhiling on 9/7/22.
//

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../../include/all.h"
#define AF_INET     2       /* Internet IP Protocol */
#define AF_INET6    10      /* IP version 6 */
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/syscalls/sys_enter_openat")
int handle_syscalls_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task;
    struct OpenFileEvent *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_OPEN;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->openFileArguments.open_dfd = BPF_CORE_READ(ctx, args[0]);
    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->openFileArguments.open_filename, sizeof(e->openFileArguments.open_filename), filename_ptr);

    e->openFileArguments.open_flags = BPF_CORE_READ(ctx, args[2]);
    e->openFileArguments.open_mode = BPF_CORE_READ(ctx, args[3]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(do_sys_openat2_entry, int dfd, const char *filename, struct open_how *how)
{
    struct OpenFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_OPEN;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->openFileArguments.open_dfd = dfd;
    bpf_core_read_user_str(&e->openFileArguments.open_filename, sizeof(e->openFileArguments.open_filename), filename);
    bpf_core_read(&e->openFileArguments.open_flags, sizeof(e->openFileArguments.open_flags), &how->flags);
    bpf_core_read(&e->openFileArguments.open_mode, sizeof(e->openFileArguments.open_mode), &how->mode);
    //bpf_core_read(&e->how_resolve, sizeof(e->how_resolve), &how->resolve);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open_entry, struct file *file, struct path *path)
{
    struct OpenFileEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_OPEN;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* FAILED TO FETCH */
    char *filename_ptr;
    filename_ptr = (char *)BPF_CORE_READ(file, f_path.dentry, d_iname);
    bpf_core_read_user_str(&e->openFileArguments.open_filename, sizeof(e->openFileArguments.open_filename), filename_ptr);

    short file_mode_raw = BPF_CORE_READ(file, f_inode, i_mode);
    int mask = 0xfff;
    e->openFileArguments.open_mode = file_mode_raw & mask;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int handle_syscalls_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct DeleteEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();
    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_DELETE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->deleteArguments.delete_dfd = BPF_CORE_READ(ctx, args[0]);
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->deleteArguments.delete_pathname, sizeof(e->deleteArguments.delete_pathname), pathname_ptr);
    e->deleteArguments.delete_flag = BPF_CORE_READ(ctx, args[2]);

    /* successfully submit it to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int handle_syscalls_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct Renameat2Event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_RENAMEAT_2;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->renameat2Arguments.rename_olddfd = BPF_CORE_READ(ctx, args[0]);
    e->renameat2Arguments.rename_newdfd = BPF_CORE_READ(ctx, args[2]);
    e->renameat2Arguments.rename_flags = BPF_CORE_READ(ctx, args[4]);

    char *oldname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->renameat2Arguments.rename_oldname, sizeof(e->renameat2Arguments.rename_oldname), oldname_ptr);
    char *newname_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    bpf_probe_read_user_str(&e->renameat2Arguments.rename_newname, sizeof(e->renameat2Arguments.rename_newname), newname_ptr);

    /* successfully submit it to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmodat")
int handle_syscalls_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    struct ChangeModeEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_CHANGE_MODE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->changeModeArguments.chmod_dfd = BPF_CORE_READ(ctx, args[0]);
    e->changeModeArguments.chmod_mode = BPF_CORE_READ(ctx, args[2]);

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->changeModeArguments.chmod_filename, sizeof(e->changeModeArguments.chmod_filename), name_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_newlstat")
int handle_syscalls_newlstat(struct trace_event_raw_sys_enter *ctx)
{
    struct GetModeEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_GET_MODE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->getModeArguments.stat_filename, sizeof(e->getModeArguments.stat_filename), name_ptr);

    struct stat *stat_buf = (struct stat*)BPF_CORE_READ(ctx, args[1]);
    short file_mode_raw = BPF_CORE_READ_USER(stat_buf, st_mode);
    int mask = 0xfff;
    e->getModeArguments.stat_mode = file_mode_raw & mask;

    bpf_core_read_user(&e->getModeArguments.stat_uid, sizeof(e->getModeArguments.stat_uid), &stat_buf->st_uid);
    bpf_core_read_user(&e->getModeArguments.stat_gid, sizeof(e->getModeArguments.stat_gid), &stat_buf->st_gid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_chdir")
int handle_syscalls_chdir(struct trace_event_raw_sys_enter *ctx)
{
    struct ChangeDirEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_CHANGE_DIR;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->changeDirArguments.chdir_filename, sizeof(e->changeDirArguments.chdir_filename), name_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mkdir")
int handle_syscalls_mkdir(struct trace_event_raw_sys_enter *ctx)
{
    struct MakeDirEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_MAKE_DIR;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->makeDirArguments.mkdir_filename, sizeof(e->makeDirArguments.mkdir_filename), name_ptr);

    e->makeDirArguments.mkdir_mode = BPF_CORE_READ(ctx, args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_rmdir")
int handle_syscalls_rmdir(struct trace_event_raw_sys_enter *ctx)
{
    struct RemoveDirEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_REMOVE_DIR;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    char *name_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->removeDirArguments.rmdir_filename, sizeof(e->removeDirArguments.rmdir_filename), name_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry, struct file *file, char *buf, size_t count, loff_t *pos)
{
    struct ReadFileEvent *e;
    struct task_struct *task;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_READ_FILE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->readFileArguments.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    e->readFileArguments.rdev = BPF_CORE_READ(file, f_inode, i_rdev);
    e->readFileArguments.inode = BPF_CORE_READ(file, f_inode, i_ino);
    e->readFileArguments.read_bytes = count;

    // get filename
    char *filename_ptr;
    filename_ptr = (char *)BPF_CORE_READ(file, f_path.dentry, d_iname);
    bpf_probe_read_kernel_str(e->event.filename, sizeof(e->event.filename), filename_ptr);

    // get file auth
    short file_mode_raw = BPF_CORE_READ(file, f_inode, i_mode);
    int mask = 0xfff;
    e->readFileArguments.filemode = file_mode_raw & mask;

    // get file user
    e->readFileArguments.fileuser = BPF_CORE_READ(file, f_inode, i_uid.val);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    struct WriteFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_WRITE_FILE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    e->writeFileArguments.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    e->writeFileArguments.rdev = BPF_CORE_READ(file, f_inode, i_rdev);
    e->writeFileArguments.inode = BPF_CORE_READ(file, f_inode, i_ino);
    e->writeFileArguments.write_bytes = count;

    // get filename
    char *filename_ptr;
    filename_ptr = (char *)BPF_CORE_READ(file, f_path.dentry, d_iname);
    bpf_probe_read_kernel_str(e->event.filename, sizeof(e->event.filename), filename_ptr);

    // get file auth
    short file_mode_raw = BPF_CORE_READ(file, f_inode, i_mode);
    int mask = 0xfff;
    e->writeFileArguments.filemode = file_mode_raw & mask;

    // get file user
    e->writeFileArguments.fileuser = BPF_CORE_READ(file, f_inode, i_uid.val);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


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

SEC("tp/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx)
{
    struct SocketEvent *e;
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
    e->event.event_type = EVENT_NETWORK_SOCKET;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->socketArguments.family, sizeof(e->socketArguments.family), &ctx->args[0]);
    bpf_core_read(&e->socketArguments.type, sizeof(e->socketArguments.type), &ctx->args[1]);
    bpf_core_read(&e->socketArguments.protocol, sizeof(e->socketArguments.protocol), &ctx->args[2]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct TcpIpv4ConnectEvent *e;
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
    e->event.event_type = EVENT_NETWORK_TCP_IPV4;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->tcpIpv4ConnectArguments.addr_len, sizeof(e->tcpIpv4ConnectArguments.addr_len), &addr_len);

    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    e->tcpIpv4ConnectArguments.sin_family = BPF_CORE_READ(sin, sin_family);
    e->tcpIpv4ConnectArguments.sin_port = BPF_CORE_READ(sin, sin_port);
    e->tcpIpv4ConnectArguments.s_addr = BPF_CORE_READ(sin, sin_addr.s_addr);

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

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone")
// trace_event_raw_sys_enter or CloneArguments ?
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

/// Kellect version 1.1

SEC("tp/syscalls/sys_enter_dup")
int handle_dup(struct trace_event_raw_sys_enter *ctx)
{
    struct DupFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_DUP;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->dupFileArguments.dup_fildes = BPF_CORE_READ(ctx, args[0]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_dup2")
int handle_dup2(struct trace_event_raw_sys_enter *ctx)
{
    struct Dup2FileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_DUP_2;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->dup2FileArguments.dup2_oldfd = BPF_CORE_READ(ctx, args[0]);
    e->dup2FileArguments.dup2_newfd = BPF_CORE_READ(ctx, args[1]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx)
{
    struct CloseFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_CLOSE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->closeFileArguments.close_fd = BPF_CORE_READ(ctx, args[0]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_ftruncate")
int handle_file_ftruncate(struct trace_event_raw_sys_enter *ctx)
{
    struct FtruncateFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_FTRUNCATE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->ftruncateFileArguments.ftruncate_fd = BPF_CORE_READ(ctx, args[0]);
    e->ftruncateFileArguments.ftruncate_length = BPF_CORE_READ(ctx, args[1]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_chmod")
int handle_file_chmod(struct trace_event_raw_sys_enter *ctx)
{
    struct ChmodFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_CHMOD;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->chmodFileArguments.chmod_pathname, sizeof(e->chmodFileArguments.chmod_pathname), pathname_ptr);

    e->chmodFileArguments.mode = BPF_CORE_READ(ctx, args[1]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchdir")
int handle_file_fchdir(struct trace_event_raw_sys_enter *ctx)
{
    struct FchdirFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_FCHDIR;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->fchdirFileArguments.fchdir_fd = BPF_CORE_READ(ctx, args[0]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_link")
int handle_file_link(struct trace_event_raw_sys_enter *ctx)
{
    struct LinkFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_LINK;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    char *old_name_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->linkFileArguments.link_oldpath, sizeof(e->linkFileArguments.link_oldpath), old_name_ptr);

    char *new_name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->linkFileArguments.link_newpath, sizeof(e->linkFileArguments.link_newpath), new_name_ptr);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_linkat")
int handle_file_linkat(struct trace_event_raw_sys_enter *ctx)
{
    struct LinkatFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_LINKAT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->linkatFileArguments.linkat_olddfd = BPF_CORE_READ(ctx, args[0]);

    char *old_name_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->linkatFileArguments.linkat_oldname, sizeof(e->linkatFileArguments.linkat_oldname), old_name_ptr);

    e->linkatFileArguments.linkat_newdfd = BPF_CORE_READ(ctx, args[2]);

    char *new_name_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    bpf_probe_read_user_str(&e->linkatFileArguments.linkat_newname, sizeof(e->linkatFileArguments.linkat_newname), new_name_ptr);

    e->linkatFileArguments.linkat_flags = BPF_CORE_READ(ctx, args[4]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmod")
int handle_file_fchmod(struct trace_event_raw_sys_enter *ctx)
{
    struct FchmodFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_FCHMOD;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->fchmodFileArguments.fchmod_fd = BPF_CORE_READ(ctx, args[0]);
    e->fchmodFileArguments.fchmod_mode = BPF_CORE_READ(ctx, args[1]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mkdirat")
int handle_file_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
    struct MkdiratFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_MKDIRAT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->mkdiratFileArguments.mkdirat_dfd = BPF_CORE_READ(ctx, args[0]);

    char *pathname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->mkdiratFileArguments.mkdirat_name, sizeof(e->mkdiratFileArguments.mkdirat_name), pathname_ptr);

    e->mkdiratFileArguments.mkdirat_mode = BPF_CORE_READ(ctx, args[2]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int handle_file_rename(struct trace_event_raw_sys_enter *ctx)
{
    struct RenameFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_RENAME;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    char *oldname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->renameFileArguments.rename_oldname, sizeof(e->renameFileArguments.rename_oldname), oldname_ptr);
    char *newname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->renameFileArguments.rename_newname, sizeof(e->renameFileArguments.rename_newname), newname_ptr);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int handle_file_renameat(struct trace_event_raw_sys_enter *ctx)
{
    struct RenameatFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_RENAMEAT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->renameatFileArguments.renameat_oldfd = BPF_CORE_READ(ctx, args[0]);
    e->renameatFileArguments.renameat_newfd = BPF_CORE_READ(ctx, args[2]);

    char *oldname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->renameatFileArguments.renameat_oldname, sizeof(e->renameatFileArguments.renameat_oldname), oldname_ptr);
    char *newname_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    bpf_probe_read_user_str(&e->renameatFileArguments.renameat_newname, sizeof(e->renameatFileArguments.renameat_newname), newname_ptr);


    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_symlink")
int handle_file_symlink(struct trace_event_raw_sys_enter *ctx)
{
    struct SymlinkFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_SYMLINK;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    char *oldname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->symlinkFileArguments.symlink_oldname, sizeof(e->symlinkFileArguments.symlink_oldname), oldname_ptr);
    char *newname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->symlinkFileArguments.symlink_newname, sizeof(e->symlinkFileArguments.symlink_newname), newname_ptr);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_symlinkat")
int handle_file_symlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct SymlinkatFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_SYMLINKAT;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    char *oldname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->symlinkatFileArguments.symlinkat_oldname, sizeof(e->symlinkatFileArguments.symlinkat_oldname), oldname_ptr);
    e->symlinkatFileArguments.symlinkat_fd = BPF_CORE_READ(ctx, args[1]);
    char *newname_ptr = (char *)BPF_CORE_READ(ctx, args[2]);
    bpf_probe_read_user_str(&e->symlinkatFileArguments.symlinkat_newname, sizeof(e->symlinkatFileArguments.symlinkat_newname), newname_ptr);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int handle_file_unlink(struct trace_event_raw_sys_enter *ctx)
{
    struct UnlinkFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_UNLINK;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    char *oldname_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->unlinkFileArguments.unlink_name, sizeof(e->unlinkFileArguments.unlink_name), oldname_ptr);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_truncate")
int handle_file_truncate(struct trace_event_raw_sys_enter *ctx)
{
    struct TruncateFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_TRUNCATE;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    char *path_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->truncateFileArguments.truncate_path, sizeof(e->truncateFileArguments.truncate_path), path_ptr);
    e->truncateFileArguments.length = BPF_CORE_READ(ctx, args[1]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_pread64")
int handle_file_pread64(struct trace_event_raw_sys_enter *ctx)
{
    struct Pread64FileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_PREAD64;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->pread64FileArguments.read_fd = BPF_CORE_READ(ctx, args[0]);
    //char *ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    //bpf_probe_read_user_str(&e->pread64FileArguments.read_buff, sizeof(e->pread64FileArguments.read_buff), ptr);
    e->pread64FileArguments.read_size = BPF_CORE_READ(ctx, args[2]);
    e->pread64FileArguments.read_pos = BPF_CORE_READ(ctx, args[3]);


    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_preadv")
int handle_file_preadv(struct trace_event_raw_sys_enter *ctx)
{
    struct PreadvFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_PREADV;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->preadvFileArguments.read_fd = BPF_CORE_READ(ctx, args[0]);
    e->preadvFileArguments.read_vlen = BPF_CORE_READ(ctx, args[2]);
    e->preadvFileArguments.read_pos_l = BPF_CORE_READ(ctx, args[3]);
    e->preadvFileArguments.read_pos_h = BPF_CORE_READ(ctx, args[4]);


    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_pwrite64")
int handle_file_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
    struct Pwrite64FileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_PWRITE64;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->pwrite64FileArguments.write_fd = BPF_CORE_READ(ctx, args[0]);
    e->pwrite64FileArguments.write_size = BPF_CORE_READ(ctx, args[2]);
    e->pwrite64FileArguments.write_pos = BPF_CORE_READ(ctx, args[3]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_pwritev")
int handle_file_pwritev(struct trace_event_raw_sys_enter *ctx)
{
    struct PwritevFileEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_FILE_PWRITEV;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->pwritevFileArguments.write_fd = BPF_CORE_READ(ctx, args[0]);
    e->pwritevFileArguments.write_vlen = BPF_CORE_READ(ctx, args[2]);
    e->pwritevFileArguments.write_pos_l = BPF_CORE_READ(ctx, args[3]);
    e->pwritevFileArguments.write_pos_h = BPF_CORE_READ(ctx, args[4]);


    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx)
{
    struct SetgidEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_SETGID;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->setgidArguments.gid = BPF_CORE_READ(ctx, args[0]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct SetuidEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_SETUID;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->setuidArguments.uid = BPF_CORE_READ(ctx, args[0]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setregid")
int handle_setregid(struct trace_event_raw_sys_enter *ctx)
{
    struct SetregidEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_SETREGID;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->setregidArguments.setregid_rgid = BPF_CORE_READ(ctx, args[0]);
    e->setregidArguments.setregid_egid = BPF_CORE_READ(ctx, args[1]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setresgid")
int handle_setresgid(struct trace_event_raw_sys_enter *ctx)
{
    struct SetresgidEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_SETRESGID;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->setresgidArguments.setresgid_rgid = BPF_CORE_READ(ctx, args[0]);
    e->setresgidArguments.setresgid_egid = BPF_CORE_READ(ctx, args[1]);
    e->setresgidArguments.setresgid_sgid = BPF_CORE_READ(ctx, args[2]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setresuid")
int handle_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    struct SetresuidEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_SETRESUID;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->setresuidArguments.setresuid_ruid = BPF_CORE_READ(ctx, args[0]);
    e->setresuidArguments.setresuid_euid = BPF_CORE_READ(ctx, args[1]);
    e->setresuidArguments.setresuid_suid = BPF_CORE_READ(ctx, args[2]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setreuid")
int handle_setreuid(struct trace_event_raw_sys_enter *ctx)
{
    struct SetreuidEvent *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if(!e){
        bpf_printk("buffer is overflowed, event is losing\n");
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();

    e->event.pid = BPF_CORE_READ(task, pid);
    e->event.ppid = BPF_CORE_READ(task, tgid);
    e->event.event_type = EVENT_SETREUID;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    //special arguments
    e->setreuidArguments.setreuid_ruid = BPF_CORE_READ(ctx, args[0]);
    e->setreuidArguments.setreuid_euid = BPF_CORE_READ(ctx, args[1]);

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
