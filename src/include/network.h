// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef KELLECT_LINUX_NETWORK_H
#define KELLECT_LINUX_NETWORK_H

#define TASK_COMM_LEN 64
#define MAX_FILENAME_LEN 127

typedef unsigned int __u32;
typedef __u32 u32;

enum EventType
{
    EVENT_NETWORK_CONNECT = 201,
    EVENT_NETWORK_DISCONNECT = 202,
    EVENT_NETWORK_SENDTO = 203,
    EVENT_NETWORK_RECVFROM = 204,
    EVENT_NETWORK_SENDMSG = 205,
    EVENT_NETWORK_RECVMSG = 206,
    EVENT_NETWORK_ACCEPT = 207,
    EVENT_NETWORK_ACCEPT4=208,
    EVENT_NETWORK_BIND = 209,
    EVENT_NETWORK_GETPEERNAME=210,
    EVENT_NETWORK_RECVMMSG=211,
    EVENT_NETWORK_SOCKETPAIR=212,
    EVENT_NETWORK_SENDMMSG=213
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
    int addrlen;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct ConnectEvent
{
    struct Event event;
    struct ConnectArguments connectArguments;
};

struct SendArguments
{
    int fd;
    void *buff;
    unsigned int len;  // maybe size_t
    unsigned int flags;
    int addr_len;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct SendEvent
{
    struct Event event;
    struct SendArguments sendArguments;
};

struct RecvArguments
{
    int fd;
    void *buff;
    unsigned int len;  // maybe size_t
    unsigned int flags;
    int addr_len;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct RecvEvent
{
    struct Event event;
    struct RecvArguments recvArguments;
};

struct SendRecvMsgArguments
{
    int fd;
    unsigned int flags;
    unsigned int msg_flags; 
    int addr_len;
    unsigned short sa_family; // Socket type
    uint32_t s_addr;  // IPv4 address
    uint16_t s_port;  // IPv4, IPv6 port
    struct in6_addr *s_addr_v6; // IPv6 address
};

struct SendRecvMsgEvent
{
    struct Event event;
    struct SendRecvMsgArguments sendRecvMsgArguments;
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
#endif
