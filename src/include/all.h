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
    /// kellect v1.0
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
    EVENT_PROCESS_MPROTECT = 21,

    EVENT_FILE_OPEN = 101,
    EVENT_FILE_DELETE = 102,
    EVENT_FILE_RENAMEAT_2 = 103,
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
    EVENT_NETWORK_RECV = 206,
    
    EVENT_NETWORK_ACCEPT = 207,
    EVENT_NETWORK_ACCEPT4=208,
    EVENT_NETWORK_BIND = 209,
    EVENT_NETWORK_GETPEERNAME=210,
    EVENT_NETWORK_RECVMMSG=211,
    EVENT_NETWORK_SOCKETPAIR=212,
    EVENT_NETWORK_SENDMMSG=213,


    ///zhengyulin 20230718
    EVENT_FILE_DUP = 111,
    EVENT_FILE_CLOSE = 112,
    EVENT_FILE_FTRUNCATE = 113,
    EVENT_FILE_CHMOD = 114,
    EVENT_FILE_FCHDIR = 115,
    EVENT_FILE_LINK = 116,
    EVENT_FILE_LINKAT = 117,
    EVENT_FILE_FCHMOD = 118,
    EVENT_FILE_MKDIRAT = 119,
    EVENT_FILE_RENAME = 120,
    EVENT_FILE_SYMLINK = 121,
    EVENT_FILE_SYMLINKAT = 122,
    EVENT_FILE_UNLINK = 123,
    EVENT_FILE_TRUNCATE = 124,
    EVENT_FILE_DUP_2 = 125,
    EVENT_FILE_RENAMEAT = 126,
    EVENT_FILE_PREAD64 = 127,
    EVENT_FILE_PREADV = 128,
    EVENT_FILE_PWRITE64 = 129,
    EVENT_FILE_PWRITEV = 130,
    //EVENT_FILE_READ = 131,
    //EVENT_FILE_READV = 132,
    //EVENT_FILE_WRITE = 133,
    //EVENT_FILE_WRITEV = 134,


    ///zhengyulin 20230725
    EVENT_SETGID = 301,
    EVENT_SETUID = 302,
    EVENT_SETREGID = 303,
    EVENT_SETRESGID = 304,
    EVENT_SETRESUID = 305,
    EVENT_SETREUID = 306,

    //EVENT_NETWORK_ACCEPT = 307,
    //EVENT_NETWORK_GETPEERNAME = 308,
    //EVENT_NETWORK_SOCKETPAIR = 309
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

struct Renameat2Arguments {
    int rename_olddfd;
    char rename_oldname[MAX_FILENAME_LEN];
    int rename_newdfd;
    char rename_newname[MAX_FILENAME_LEN];
    unsigned int rename_flags;
};

struct Renameat2Event {
    struct Event event;
    struct Renameat2Arguments renameat2Arguments;
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

struct DupFileArguments{
    int dup_fildes;
};

struct DupFileEvent{
    struct Event event;
    struct DupFileArguments dupFileArguments;
};

struct Dup2FileArguments{
    int dup2_oldfd;
    int dup2_newfd;
};

struct Dup2FileEvent{
    struct Event event;
    struct Dup2FileArguments dup2FileArguments;
};

struct CloseFileArguments{
    int close_fd;
};

struct CloseFileEvent{
    struct Event event;
    struct CloseFileArguments closeFileArguments;
};

struct FtruncateFileArguments{
    int ftruncate_fd;
    int ftruncate_length;
};

struct FtruncateFileEvent{
    struct Event event;
    struct FtruncateFileArguments ftruncateFileArguments;
};

struct ChmodFileArguments{
    char chmod_pathname[MAX_FILENAME_LEN];
    int mode;
};

struct ChmodFileEvent{
    struct Event event;
    struct ChmodFileArguments chmodFileArguments;
};

struct FchdirFileArguments{
    int fchdir_fd;
};

struct FchdirFileEvent{
    struct Event event;
    struct FchdirFileArguments fchdirFileArguments;
};

struct LinkFileArguments{
    char link_oldpath[MAX_FILENAME_LEN];
    char link_newpath[MAX_FILENAME_LEN];
};

struct LinkFileEvent{
    struct Event event;
    struct LinkFileArguments linkFileArguments;
};

struct LinkatFileArguments{
    int linkat_olddfd;
    char linkat_oldname[MAX_FILENAME_LEN];
    int linkat_newdfd;
    char linkat_newname[MAX_FILENAME_LEN];
    int linkat_flags;
};

struct LinkatFileEvent{
    struct Event event;
    struct LinkatFileArguments linkatFileArguments;
};

struct FchmodFileArguments{
    int fchmod_fd;
    int fchmod_mode;
};

struct FchmodFileEvent{
    struct Event event;
    struct FchmodFileArguments fchmodFileArguments;
};

struct MkdiratFileArguments{
    int mkdirat_dfd;
    char mkdirat_name[MAX_FILENAME_LEN];
    short mkdirat_mode;
};

struct MkdiratFileEvent{
    struct Event event;
    struct MkdiratFileArguments mkdiratFileArguments;
};

struct RenameFileArguments{
    char rename_oldname[MAX_FILENAME_LEN];
    char rename_newname[MAX_FILENAME_LEN];
};

struct RenameFileEvent{
    struct Event event;
    struct RenameFileArguments renameFileArguments;
};

struct RenameatFileArguments {
    int renameat_oldfd;
    char renameat_oldname[MAX_FILENAME_LEN];
    int renameat_newfd;
    char renameat_newname[MAX_FILENAME_LEN];
};

struct RenameatFileEvent {
    struct Event event;
    struct RenameatFileArguments renameatFileArguments;
};

struct SymlinkFileArguments{
    char symlink_oldname[MAX_FILENAME_LEN];
    char symlink_newname[MAX_FILENAME_LEN];
};

struct SymlinkFileEvent{
    struct Event event;
    struct SymlinkFileArguments symlinkFileArguments;
};

struct SymlinkatFileArguments{
    char symlinkat_oldname[MAX_FILENAME_LEN];
    int symlinkat_fd;
    char symlinkat_newname[MAX_FILENAME_LEN];
};

struct SymlinkatFileEvent{
    struct Event event;
    struct SymlinkatFileArguments symlinkatFileArguments;
};

struct UnlinkFileArguments{
    char unlink_name[MAX_FILENAME_LEN];
};

struct UnlinkFileEvent{
    struct Event event;
    struct UnlinkFileArguments unlinkFileArguments;
};

struct TruncateFileArguments{
    char truncate_path[MAX_FILENAME_LEN];
    int length;
};

struct TruncateFileEvent{
    struct Event event;
    struct TruncateFileArguments truncateFileArguments;
};

struct Pread64FileArguments{
    int read_fd;
    //char read_buff[MAX_BUFF_LEN];
    int read_size;
    int read_pos;
};

struct Pread64FileEvent{
    struct Event event;
    struct Pread64FileArguments pread64FileArguments;
};

struct PreadvFileArguments{
    int read_fd;
    int read_vlen;
    int read_pos_l;
    int read_pos_h;
};

struct PreadvFileEvent{
    struct Event event;
    struct PreadvFileArguments preadvFileArguments;
};

struct Pwrite64FileArguments{
    int write_fd;
    int write_size;
    int write_pos;
};

struct Pwrite64FileEvent{
    struct Event event;
    struct Pwrite64FileArguments pwrite64FileArguments;
};

struct PwritevFileArguments{
    int write_fd;
    int write_vlen;
    int write_pos_l;
    int write_pos_h;
};

struct PwritevFileEvent{
    struct Event event;
    struct PwritevFileArguments pwritevFileArguments;
};

//////////////////////////////////////// USER //////////////////////////////////////////////////

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
struct AcceptArguments
{
    int fd;
    int upper_addrlen;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};
struct AcceptEvent
{
    struct Event event;
    struct AcceptArguments acceptArguments;
};
struct Accept4Arguments
{
    int fd;
    int upper_addrlen;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    int flags;
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct Accept4Event
{
    struct Event event;
    struct Accept4Arguments accept4Arguments;
};
struct BindArguments
{
    int fd;
    int addrlen;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct BindEvent
{
    struct Event event;
    struct BindArguments bindArguments;
};
struct GetPeerNameArguments
{
    int fd;
    int addr_len;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct GetPeerNameEvent
{
    struct Event event;
    struct GetPeerNameArguments getpeernameArguments;
};
struct RecvMmsgArguments
{
    int fd;
    unsigned int flags;
    unsigned int mmsg_flags; 
    unsigned int vlen;
    
    int addr_len;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct RecvMmsgEvent
{
    struct Event event;
    struct RecvMmsgArguments recvmmsgArguments;
};
struct SendMmsgArguments
{
    int fd;
    unsigned int flags;
    unsigned int mmsg_flags; 
    unsigned int vlen;
    
    int addr_len;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct SendMmsgEvent
{
    struct Event event;
    struct SendMmsgArguments sendmmsgArguments;
};
struct SocketPairArguments
{
    int family;
    unsigned int type;
    unsigned int protocol; 
    int sv1;
    int sv2;
    
    int addr_len;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
    
};

struct SocketPairEvent
{
    struct Event event;
    struct SocketPairArguments socketpairArguments;
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
#endif //KELLECT_LINUX_DEMO_H
