#ifndef KELLECT_LINUX_NETWORK_H
#define KELLECT_LINUX_NETWORK_H

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

    EVENT_FILE_OPEN = 101,
    EVENT_FILE_DELETE = 102,
    EVENT_FILE_RENAME = 103,
    EVENT_FILE_CHANGE_MODE = 104,
    EVENT_FILE_GET_MODE = 105,
    EVENT_FILE_CHANGE_DIR = 106,
    EVENT_FILE_MAKE_DIR = 107,
    EVENT_FILE_REMOVE_DIR = 108,

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

#endif
