/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __FORK_H
#define __FORK_H

#define TASK_COMM_LEN 64
#define MAX_FILENAME_LEN 127

typedef unsigned int __u32;
typedef __u32 u32;

enum EventType
{
    EVENT_FORK = 1,
    EVENT_EXEC = 2,
    EVENT_EXIT = 3,
    EVENT_OPEN = 4,
    EVENT_CLOSE = 5,
    EVENT_READ = 6,
    EVENT_WRITE = 7,
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

struct ForkArguments {

};


struct ForkEvent {
    struct Event event;
    struct CloneArguments cloneArguments;
    int a;
    int b;
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


#endif /* __FORK_H */
