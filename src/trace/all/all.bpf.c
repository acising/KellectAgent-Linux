// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Created by zhuzhiling on 9/7/22.
//

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../../include/all.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

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
    struct RenameEvent *e;
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

    e->renameArguments.rename_olddfd = BPF_CORE_READ(ctx, args[0]);
    e->renameArguments.rename_newdfd = BPF_CORE_READ(ctx, args[2]);
    e->renameArguments.rename_flags = BPF_CORE_READ(ctx, args[4]);

    char *oldname_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_user_str(&e->renameArguments.rename_oldname, sizeof(e->renameArguments.rename_oldname), oldname_ptr);
    char *newname_ptr = (char *)BPF_CORE_READ(ctx, args[3]);
    bpf_probe_read_user_str(&e->renameArguments.rename_newname, sizeof(e->renameArguments.rename_newname), newname_ptr);

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

SEC("tp/syscalls/sys_enter_newstat")
int handle_syscalls_newstat(struct trace_event_raw_sys_enter *ctx)
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
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
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

    bpf_core_read(&e->exitArguments.pid, sizeof(e->exitArguments.pid), &ctx->pid);
    bpf_core_read_str(&e->exitArguments.comm, sizeof(e->exitArguments.comm), &ctx->comm);
    bpf_core_read(&e->exitArguments.prio, sizeof(e->exitArguments.prio), &ctx->prio);
    e->exitArguments.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
