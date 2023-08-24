// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef KELLECT_LINUX_FILE_H
#define KELLECT_LINUX_FILE_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_BUFF_LEN 100

enum EventType {
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

//////////////////////////////////////////////////////// ZHENGYULIN 20230718 ////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////network///////////////////////
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

#endif //KELLECT_LINUX_FILE_H
