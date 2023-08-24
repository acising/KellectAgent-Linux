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
    e->event.event_type = EVENT_FILE_RENAME;
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


    e->readFileArguments.res = PT_REGS_RC(ctx);
    bpf_core_read(&e->readFileArguments.ss, sizeof(e->readFileArguments.ss), &ctx->ss);
    bpf_core_read(&e->readFileArguments.sp, sizeof(e->readFileArguments.sp), &ctx->sp);
    bpf_core_read(&e->readFileArguments.r14, sizeof(e->readFileArguments.r14), &ctx->flags);

    e->readFileArguments.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    e->readFileArguments.rdev = BPF_CORE_READ(file, f_inode, i_rdev);
    e->readFileArguments.inode = BPF_CORE_READ(file, f_inode, i_ino);

    // get filename
    char *filename_ptr;
    filename_ptr = (char *)BPF_CORE_READ(file, f_path.dentry, d_iname);
    bpf_probe_read_kernel_str(e->event.filename, sizeof(e->event.filename), filename_ptr);

//    // get file path
//    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_d_path)) {
//        /* get path only if 'bpf_d_path' is available */
//        struct path cur_path = BPF_CORE_READ(file, f_path);
//        char *file_path;
//        int error = bpf_d_path(&cur_path, file_path, sizeof(file_path));
//        if (error >= 0) {
//            bpf_probe_read_kernel_str(e->readFileArguments.filepath, sizeof(e->readFileArguments.filepath), file_path);
//        } else {
//            char *error_msg = "Read path error.";
//            bpf_probe_read_kernel_str(e->readFileArguments.filepath, sizeof(e->readFileArguments.filepath), error_msg);
//        }
//    }
//    else {
//        char *error_msg = "Read path error.";
//        bpf_probe_read_kernel_str(e->readFileArguments.filepath, sizeof(e->readFileArguments.filepath), error_msg);
//    }

    // get file auth
    short file_mode_raw = BPF_CORE_READ(file, f_inode, i_mode);
    int mask = 0xfff;
    e->readFileArguments.filemode = file_mode_raw & mask;

    // get file user
    e->readFileArguments.fileuser = BPF_CORE_READ(file, f_inode, i_uid.val);

    e->readFileArguments.flags = 1;
    e->readFileArguments.read_bytes = count;

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

    e->writeFileArguments.res = PT_REGS_RC(ctx);
    bpf_core_read(&e->writeFileArguments.ss, sizeof(e->writeFileArguments.ss), &ctx->ss);
    bpf_core_read(&e->writeFileArguments.sp, sizeof(e->writeFileArguments.sp), &ctx->sp);
    bpf_core_read(&e->writeFileArguments.r14, sizeof(e->writeFileArguments.r14), &ctx->flags);

    e->writeFileArguments.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    e->writeFileArguments.rdev = BPF_CORE_READ(file, f_inode, i_rdev);
    e->writeFileArguments.inode = BPF_CORE_READ(file, f_inode, i_ino);

    // get filename
    char *filename_ptr;
    filename_ptr = (char *)BPF_CORE_READ(file, f_path.dentry, d_iname);
    bpf_probe_read_kernel_str(e->event.filename, sizeof(e->event.filename), filename_ptr);

//    // get file path
//    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_d_path)) {
//        /* get path only if 'bpf_d_path' is available */
//        struct path cur_path = BPF_CORE_READ(file, f_path);
//        char *file_path;
//        int error = bpf_d_path(&cur_path, file_path, sizeof(file_path));
//        if (error >= 0) {
//            bpf_probe_read_kernel_str(e->writeFileArguments.filepath, sizeof(e->writeFileArguments.filepath),
//                                      file_path);
//        } else {
//            char *error_msg = "Read path error.";
//            bpf_probe_read_kernel_str(e->writeFileArguments.filepath, sizeof(e->writeFileArguments.filepath),
//                                      error_msg);
//        }
//    }
//    else {
//        char *error_msg = "Read path error.";
//        bpf_probe_read_kernel_str(e->writeFileArguments.filepath, sizeof(e->writeFileArguments.filepath), error_msg);
//    }

    // get file auth
    short file_mode_raw = BPF_CORE_READ(file, f_inode, i_mode);
    int mask = 0xfff;
    e->writeFileArguments.filemode = file_mode_raw & mask;

    // get file user
    e->writeFileArguments.fileuser = BPF_CORE_READ(file, f_inode, i_uid.val);

    e->writeFileArguments.flags = 2;
    e->writeFileArguments.write_bytes = count;

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

    struct sockaddr *sock = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);
    bpf_core_read_user(&e->connectArguments.sa_family, sizeof(e->connectArguments.sa_family), &sock->sa_family);
    bpf_core_read_user(&e->connectArguments.sa_data, sizeof(e->connectArguments.sa_data), &sock->sa_data);

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

SEC("tp/net/net_dev_xmit")
int handle_send(struct trace_event_raw_net_dev_xmit *ctx)
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
    e->event.event_type = EVENT_NETWORK_SEND;
    e->event.is_process = e->event.pid == e->event.ppid;

    e->event.user_mode_time = BPF_CORE_READ(task, utime);
    e->event.kernel_mode_time = BPF_CORE_READ(task, stime);
    e->event.voluntary_context_switch_count = BPF_CORE_READ(task, nvcsw);
    e->event.involuntary_context_switch_count = BPF_CORE_READ(task, nivcsw);
    e->event.start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(&e->event.comm, sizeof(e->event.comm));

    bpf_core_read(&e->sendArguments.len, sizeof(e->sendArguments.len), &ctx->len);
    bpf_core_read(&e->sendArguments.rc, sizeof(e->sendArguments.rc), &ctx->rc);

    unsigned name_off;
    name_off = ctx->__data_loc_name & 0xFFFF;
    bpf_probe_read_str(&e->event.filename, sizeof(e->event.filename), (void *)ctx + name_off);

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

SEC("tp/syscalls/sys_enter_exit")
int handle_sys_exit(struct trace_event_raw_sys_enter *ctx)
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

    bpf_core_read(&e->exitArguments.prio, sizeof(e->exitArguments.prio), &ctx->args[0]);

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