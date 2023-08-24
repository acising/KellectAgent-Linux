// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef KELLECT_LINUX_FILE_H
#define KELLECT_LINUX_FILE_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_BUFF_LEN 100

enum EventType {
    EVENT_SETGID = 301,
    EVENT_SETUID = 302,
    EVENT_SETREGID = 303,
    EVENT_SETRESGID = 304,
    EVENT_SETRESUID = 305,
    EVENT_SETREUID = 306
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

struct SetgidArguments{
    int gid;
};

struct SetgidEvent{
    struct Event event;
    struct SetgidArguments setgidArguments;
};

struct SetuidArguments{
    int uid;
};

struct SetuidEvent{
    struct Event event;
    struct SetuidArguments setuidArguments;
};

struct SetregidArguments{
    int setregid_rgid;
    int setregid_egid;

};

struct SetregidEvent{
    struct Event event;
    struct SetregidArguments setregidArguments;
};

struct SetresgidArguments{
    int setresgid_rgid;
    int setresgid_egid;
    int setresgid_sgid;

};

struct SetresgidEvent{
    struct Event event;
    struct SetresgidArguments setresgidArguments;
};

struct SetresuidArguments{
    int setresuid_ruid;
    int setresuid_euid;
    int setresuid_suid;

};

struct SetresuidEvent{
    struct Event event;
    struct SetresuidArguments setresuidArguments;
};

struct SetreuidArguments{
    int setreuid_ruid;
    int setreuid_euid;

};

struct SetreuidEvent{
    struct Event event;
    struct SetreuidArguments setreuidArguments;
};

#endif //KELLECT_LINUX_FILE_H

