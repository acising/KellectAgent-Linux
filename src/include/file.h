// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef KELLECT_LINUX_FILE_H
#define KELLECT_LINUX_FILE_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

enum EventType {
    EVENT_PROCESS_FORK = 1,
    EVENT_PROCESS_EXEC = 2,
    EVENT_PROCESS_EXIT = 3,
    EVENT_PROCESS_OPEN = 4,
    EVENT_PROCESS_CLOSE = 5,
    EVENT_PROCESS_READ = 6,
    EVENT_PROCESS_WRITE = 7,
    EVENT_PROCESS_CLONE = 8,

    EVENT_FILE_OPEN = 101,
    EVENT_FILE_DELETE = 102,
    EVENT_FILE_RENAME = 103,
    EVENT_FILE_CHANGE_MODE = 104,
    EVENT_FILE_GET_MODE = 105,
    EVENT_FILE_CHANGE_DIR = 106,
    EVENT_FILE_MAKE_DIR = 107,
    EVENT_FILE_REMOVE_DIR = 108,
    EVENT_FILE_READ_FILE = 109,
    EVENT_FILE_WRITE_FILE = 110,

    EVENT_NETWORK_CONNECT = 201,
    EVENT_NETWORK_DISCONNECT = 202,
    EVENT_NETWORK_SOCKET = 203,
    EVENT_NETWORK_TCP_IPV4 = 204,
    EVENT_NETWORK_SEND = 205,
    EVENT_NETWORK_RECV = 206
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

struct OpenFileArguments {
    /* Open: duplicated */
    int open_dfd;
    char open_filename[MAX_FILENAME_LEN];
    int open_flags;
    short open_mode;
};

struct OpenFileEvent {
    struct Event event;
    struct OpenFileArguments openFileArguments;
};

struct DeleteArguments {
    int delete_dfd;
    char delete_pathname[MAX_FILENAME_LEN];
    int delete_flag;
};

struct DeleteEvent {
    struct Event event;
    struct DeleteArguments deleteArguments;
};

struct RenameArguments {
    int rename_olddfd;
    char rename_oldname[MAX_FILENAME_LEN];
    int rename_newdfd;
    char rename_newname[MAX_FILENAME_LEN];
    unsigned int rename_flags;
};

struct RenameEvent {
    struct Event event;
    struct RenameArguments renameArguments;
};

struct ChangeModeArguments {
    /* Change mode */
    int chmod_dfd;
    char chmod_filename[MAX_FILENAME_LEN];
    short chmod_mode;
    int chmod_uid;
    int chmod_gid;
};

struct ChangeModeEvent {
    struct Event event;
    struct ChangeModeArguments changeModeArguments;
};

struct GetModeArguments {
    /* Stat: get mode */
    char stat_filename[MAX_FILENAME_LEN];
    int stat_mode;
    int stat_uid;
    int stat_gid;
};

struct GetModeEvent {
    struct Event event;
    struct GetModeArguments getModeArguments;
};

struct ChangeDirArguments {
    /* Change dir */
    char chdir_filename[MAX_FILENAME_LEN];
    int chdir_fd;
};

struct ChangeDirEvent {
    struct Event event;
    struct ChangeDirArguments changeDirArguments;
};

struct MakeDirArguments {
    /* Make dir */
    char mkdir_filename[MAX_FILENAME_LEN];
    short mkdir_mode;
    int mkdir_dfd;
};

struct MakeDirEvent {
    struct Event event;
    struct MakeDirArguments makeDirArguments;
};

struct RemoveDirArguments {
    /* Remove dir */
    char rmdir_filename[MAX_FILENAME_LEN];
};

struct RemoveDirEvent {
    struct Event event;
    struct RemoveDirArguments removeDirArguments;
};


struct ReadFileArguments {
    __u64 inode;
    __u32 dev;
    __u32 rdev;
    __u64 read_bytes;
    int fd;
    char filepath[MAX_FILENAME_LEN];
    unsigned short filemode;
    unsigned int fileuser;
};

struct ReadFileEvent {
    struct Event event;
    struct ReadFileArguments readFileArguments;
};

struct WriteFileArguments {
    __u64 inode;
    __u32 dev;
    __u32 rdev;
    __u64 write_bytes;
    int fd;
    char filepath[MAX_FILENAME_LEN];
    unsigned short filemode;
    unsigned int fileuser;
};

struct WriteFileEvent {
    struct Event event;
    struct WriteFileArguments writeFileArguments;
};

#endif //KELLECT_LINUX_FILE_H
