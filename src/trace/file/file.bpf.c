#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../include/file.h"


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
