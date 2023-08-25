// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __FORK_H
#define __FORK_H

#define TASK_COMM_LEN 64
#define MAX_FILENAME_LEN 127

typedef unsigned int __u32;
typedef __u32 u32;


enum EventType
{
    EVENT_PROCESS_FORK = 1,
    EVENT_PROCESS_EXEC = 2,
    EVENT_PROCESS_EXIT = 3,
    EVENT_PROCESS_OPEN = 4,
    EVENT_PROCESS_CLOSE = 5,
    EVENT_PROCESS_READ = 6,
    EVENT_PROCESS_WRITE = 7,
    EVENT_PROCESS_CLONE = 8,
    EVENT_PROCESS_PIPE = 9,
    EVENT_PROCESS_PIPE2 = 10,
    EVENT_PROCESS_KILL = 11,
    EVENT_PROCESS_CLONE3 = 12,
    EVENT_PROCESS_EXECVE = 13,
    EVENT_PROCESS_EXECVEAT = 14,
    EVENT_PROCESS_EXIT_GROUP = 15,
    EVENT_PROCESS_PTRACE = 16,
    EVENT_PROCESS_TGKILL = 17,
    EVENT_PROCESS_TKILL = 18,
    EVENT_PROCESS_VFORK = 19,
    EVENT_PROCESS_MMAP = 20,
    EVENT_PROCESS_MPROTECT = 21
};


struct Event {

    // ========================== basic information ==========================
    // process id
    int pid;

    // parent process id
    int ppid;

    // process name
    char comm[TASK_COMM_LEN];

    // event type
    int event_type;

    // process or thread
    bool is_process;

    // ========================== running information ==========================

    // spend time on user mode for now
    long long unsigned int user_mode_time;

    // spend time on kernel mode for now
    long long unsigned int kernel_mode_time;

    // the count of voluntary context switch
    unsigned long voluntary_context_switch_count;

    // the count of involuntary context switch
    unsigned long involuntary_context_switch_count;

    // the time since process start, exclude sleeping time
    long long unsigned int start_time;

    // ========================== user information ==========================

    // real UID of the task
    uid_t uid;

    // real GID of the task
    gid_t gid;

    // effective UID of the task
    uid_t euid;

    // effective GID of the task
    gid_t egid;

    char filename[MAX_FILENAME_LEN];

};

struct CloneArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long clone_flags;
    unsigned long newsp;
    int * parent_tidptr;
    int * child_tidptr;
    unsigned long tls;
};

struct CloneEvent
{
    struct Event event;
    struct CloneArguments cloneArguments;
};


struct ForkArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char parent_comm[16];
	pid_t parent_pid;
	char child_comm[16];
	pid_t child_pid;
};


struct ForkEvent {
    struct Event event;
    struct ForkArguments forkArguments;
    // struct CloneArguments cloneArguments;
    // int a;
    // int b;
};

struct ExecArguments {
    u32 __data_loc_filename;
    pid_t pid;
    pid_t old_pid;
    char __data[0];
};

struct ExecEvent {
    struct Event event;
    struct ExecArguments execArguments;
};

struct ExitArguments {
    char comm[16];
	pid_t pid;
	int prio;
    int exit_code;
};

struct ExitEvent {
    struct Event event;
    struct ExitArguments exitArguments;
};

struct ReadArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned int fd;
    char * buf[8];
    size_t count;
};

struct ReadEvent {
    struct Event event;
    struct ReadArguments readArguments;
};

struct WriteArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned int fd;
    const char * buf[8];
    size_t count;
};

struct WriteEvent {
    struct Event event;
    struct WriteArguments writeArguments;
};

struct OpenArguments {
    short unsigned int common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int dfd;
    const char* filename;
    int flags;
    short unsigned int mode;
};

struct OpenEvent {
    struct Event event;
    struct OpenArguments openArguments;
};

struct CloseArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned int fd;
};

struct CloseEvent {
    struct Event event;
    struct CloseArguments closeArguments;
};

struct Clone3Arguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    //unsigned long clone_flags;
    //unsigned long newsp;
    //int * parent_tidptr;
    //int * child_tidptr;
    //unsigned long tls;
    int size;
};

struct Clone3Event
{
    struct Event event;
    struct Clone3Arguments clone3Arguments;
};

struct PipeArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int f1;
    int f2;
};

struct PipeEvent {
    struct Event event;
    struct PipeArguments pipeArguments;
};
struct Pipe2Arguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
        int f1;
    int f2;
    int flags;
};

struct Pipe2Event {
    struct Event event;
    struct Pipe2Arguments pipe2Arguments;
};
struct KillArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int pid;
    int sig;
};

struct KillEvent {
    struct Event event;
    struct KillArguments killArguments;
};
struct TgkillArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int tgid;
    int pid;
    int sig;
};

struct TgkillEvent {
    struct Event event;
    struct TgkillArguments tgkillArguments;
};
struct TkillArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int pid;
    int sig;
};

struct TkillEvent {
    struct Event event;
    struct TkillArguments tkillArguments;
};
struct ExecveArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char filename[MAX_FILENAME_LEN];
};

struct ExecveEvent {
    struct Event event;
    struct ExecveArguments execveArguments;
};
struct ExecveatArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char filename[MAX_FILENAME_LEN];
    int fd;
    int flags;
};

struct ExecveatEvent {
    struct Event event;
    struct ExecveatArguments execveatArguments;
};
struct Exit_groupArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int exit_code;
};

struct Exit_groupEvent {
    struct Event event;
    struct Exit_groupArguments exitgroupArguments;
};
struct PtraceArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long request;
    long pid;
    unsigned long addr;
    unsigned long data;
};

struct PtraceEvent
{
    struct Event event;
    struct PtraceArguments ptraceArguments;
};
struct VforkArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
};

struct VforkEvent {
    struct Event event;
    struct VforkArguments vforkArguments;
};
struct MmapArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

struct MmapEvent {
    struct Event event;
    struct MmapArguments mmapArguments;
};
struct MprotectArguments {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long start;
    size_t len;
    unsigned long prot;

};

struct MprotectEvent {
    struct Event event;
    struct MprotectArguments mprotectArguments;
};
#endif /* __FORK_H */
