// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Created by zhuzhiling on 9/7/22.
//

#ifndef KELLECT_LINUX_DEMO_H
#define KELLECT_LINUX_DEMO_H

#define TASK_COMM_LEN 64
#define MAX_FILENAME_LEN 127

typedef unsigned int __u32;
typedef __u32 u32;

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
    int flags;
    int res;
    int ss;
    int sp;
    int r14;
    /* TESTING */
    __u64 inode;
    __u32 dev;
    __u32 rdev;
    __u64 read_bytes;
    long ret;
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
    int flags;
    int res;
    int ss;
    int sp;
    int r14;
    /* TESTING */
    __u64 inode;
    __u32 dev;
    __u32 rdev;
    __u64 write_bytes;
    long ret;
    int fd;
    char filepath[MAX_FILENAME_LEN];
    unsigned short filemode;
    unsigned int fileuser;
};

struct WriteFileEvent {
    struct Event event;
    struct WriteFileArguments writeFileArguments;
};


struct ConnectArguments
{
    int fd;
    unsigned short sa_family;
    char sa_data[14];
    int addrlen;
};

struct ConnectEvent
{
    struct Event event;
    struct ConnectArguments connectArguments;
};

struct SocketArguments
{
    int family;
    int type;
    int protocol;
};

struct SocketEvent
{
    struct Event event;
    struct SocketArguments socketArguments;
};

struct TcpIpv4ConnectArguments
{
    int addr_len;
    // in: struct sockaddr_in
    unsigned short sin_family;
    unsigned short sin_port;
    // in: sockaddr_in -> struct in_addr
    uint32_t s_addr;
    char ip_addr[16];
};

struct TcpIpv4ConnectEvent
{
    struct Event event;
    struct TcpIpv4ConnectArguments tcpIpv4ConnectArguments;
};

struct SendArguments
{
    void *skbaddr;
    unsigned int len;
    int rc;
    u32 __data_loc_name;
};

struct SendEvent
{
    struct Event event;
    struct SendArguments sendArguments;
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


#endif //KELLECT_LINUX_DEMO_H
