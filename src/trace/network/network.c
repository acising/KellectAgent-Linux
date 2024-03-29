// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "../../include/network.h"
#include "network.skel.h"
#include "../../include/arg_parser.h"
#include "../../include/basic.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct Args my_args_network;

static volatile bool exiting = false;

FILE *output_network;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (my_args_network.if_debug_mode) {
        return vfprintf(stderr, format, args);
    } else {
        return 0;
    }
}

static void handle_signal(int signal) {
    exiting = true;
}

static int handle_network_event(void *ctx, void *data, size_t data_sz) {
    const struct Event *e = (struct Event *) data;
    char *process_type;

    if (e->is_process) {
        process_type = (char *) "process";
    } else {
        process_type = (char *) "thread";
    }

    /**
     * exclude the event created by kellect
     */
    if (strcmp("kellect", e->comm) == 0) {
        return 0;
    }
    /**
     * exclude the event created by terminal if the output directly
     */
    if (strcmp("gnome-terminal-", e->comm) == 0 && my_args_network.if_output_to_file == false) {
        return 0;
    }

    char *event_type;

    switch (e->event_type) {
        case EVENT_NETWORK_CONNECT: {
            event_type = (char *) "CONNECT";
            struct ConnectEvent *e = (struct ConnectEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->connectArguments.sa_family != AF_INET && e->connectArguments.sa_family != AF_INET6)
            {
                break;
            }
            
            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->connectArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->connectArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->connectArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->connectArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->connectArguments.fd,
                            e->connectArguments.addrlen,
                            e->connectArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->connectArguments.fd,
                            e->connectArguments.addrlen,
                            e->connectArguments.sa_family,
                            port,
                            ip);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->connectArguments.fd,
                           e->connectArguments.addrlen,
                           e->connectArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->connectArguments.fd,
                           e->connectArguments.addrlen,
                           e->connectArguments.sa_family,
                           port,
                           ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_SENDTO: {
            event_type = (char *) "DS_SENDTO";
            struct SendEvent *e = (struct SendEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->sendArguments.sa_family != AF_INET && e->sendArguments.sa_family != AF_INET6) {
                break;
            }

            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->sendArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->sendArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->sendArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->sendArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"len\":%d, "
                                            "\"flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendArguments.fd,
                            e->sendArguments.len,
                            e->sendArguments.flags,
                            e->sendArguments.addr_len,
                            e->sendArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendArguments.fd,
                            e->sendArguments.len,
                            e->sendArguments.flags,
                            e->sendArguments.addr_len,
                            e->sendArguments.sa_family,
                            port,
                            ip);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"len\":%d, "
                           "\"flags\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->sendArguments.fd,
                           e->sendArguments.len,
                           e->sendArguments.flags,
                           e->sendArguments.addr_len,
                           e->sendArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->sendArguments.fd,
                           e->sendArguments.len,
                           e->sendArguments.flags,
                           e->sendArguments.addr_len,
                           e->sendArguments.sa_family,
                           port,
                           ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_RECVFROM: {
            event_type = (char *) "DS_RECVFROM";
            struct RecvEvent *e = (struct RecvEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->recvArguments.sa_family != AF_INET && e->recvArguments.sa_family != AF_INET6) {
                break;
            }

            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->recvArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->recvArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->recvArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->recvArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"len\":%d, "
                                            "\"flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->recvArguments.fd,
                            e->recvArguments.len,
                            e->recvArguments.flags,
                            e->recvArguments.addr_len,
                            e->recvArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->recvArguments.fd,
                            e->recvArguments.len,
                            e->recvArguments.flags,
                            e->recvArguments.addr_len,
                            e->recvArguments.sa_family,
                            port,
                            ip);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"len\":%d, "
                           "\"flags\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->recvArguments.fd,
                           e->recvArguments.len,
                           e->recvArguments.flags,
                           e->recvArguments.addr_len,
                           e->recvArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->recvArguments.fd,
                           e->recvArguments.len,
                           e->recvArguments.flags,
                           e->recvArguments.addr_len,
                           e->recvArguments.sa_family,
                           port,
                           ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_SENDMSG: {
            event_type = (char *) "DS_SENDMSG";
            struct SendRecvMsgEvent *e = (struct SendRecvMsgEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->sendRecvMsgArguments.sa_family != AF_INET && e->sendRecvMsgArguments.sa_family != AF_INET6) {
                break;
            }

            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->sendRecvMsgArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->sendRecvMsgArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->sendRecvMsgArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->sendRecvMsgArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Msg_flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendRecvMsgArguments.fd,
                            e->sendRecvMsgArguments.flags,
                            e->sendRecvMsgArguments.msg_flags,
                            e->sendRecvMsgArguments.addr_len,
                            e->sendRecvMsgArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendRecvMsgArguments.fd,
                            e->sendRecvMsgArguments.flags,
                            e->sendRecvMsgArguments.msg_flags,
                            e->sendRecvMsgArguments.addr_len,
                            e->sendRecvMsgArguments.sa_family,
                            port,
                            ip);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"Flags\":%d, "
                           "\"Msg_flags\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->sendRecvMsgArguments.fd,
                           e->sendRecvMsgArguments.flags,
                           e->sendRecvMsgArguments.msg_flags,
                           e->sendRecvMsgArguments.addr_len,
                           e->sendRecvMsgArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %s\n",
                        getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                        e->sendRecvMsgArguments.fd,
                        e->sendRecvMsgArguments.flags,
                        e->sendRecvMsgArguments.msg_flags,
                        e->sendRecvMsgArguments.addr_len,
                        e->sendRecvMsgArguments.sa_family,
                        port,
                        ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_RECVMSG: {
            event_type = (char *) "DS_RECVMSG";
            struct SendRecvMsgEvent *e = (struct SendRecvMsgEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->sendRecvMsgArguments.sa_family != AF_INET && e->sendRecvMsgArguments.sa_family != AF_INET6) {
                break;
            }

            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->sendRecvMsgArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->sendRecvMsgArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->sendRecvMsgArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->sendRecvMsgArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Msg_flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendRecvMsgArguments.fd,
                            e->sendRecvMsgArguments.flags,
                            e->sendRecvMsgArguments.msg_flags,
                            e->sendRecvMsgArguments.addr_len,
                            e->sendRecvMsgArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendRecvMsgArguments.fd,
                            e->sendRecvMsgArguments.flags,
                            e->sendRecvMsgArguments.msg_flags,
                            e->sendRecvMsgArguments.addr_len,
                            e->sendRecvMsgArguments.sa_family,
                            port,
                            ip);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"Flags\":%d, "
                           "\"Msg_flags\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->sendRecvMsgArguments.fd,
                           e->sendRecvMsgArguments.flags,
                           e->sendRecvMsgArguments.msg_flags,
                           e->sendRecvMsgArguments.addr_len,
                           e->sendRecvMsgArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %s\n",
                        getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                        e->sendRecvMsgArguments.fd,
                        e->sendRecvMsgArguments.flags,
                        e->sendRecvMsgArguments.msg_flags,
                        e->sendRecvMsgArguments.addr_len,
                        e->sendRecvMsgArguments.sa_family,
                        port,
                        ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_ACCEPT: {
            event_type = (char *) "ACCEPT";
            struct AcceptEvent *e = (struct AcceptEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->acceptArguments.sa_family != AF_INET && e->acceptArguments.sa_family != AF_INET6)
            {
                break;
            }

            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->acceptArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->acceptArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->acceptArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->acceptArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                        "\"Timestamp\":%ld,"
                                        "\"EventName\":\"%s\", "
                                        "\"ProcessName\":\"%s\", "
                                        "\"ProcessID\":%d, "
                                        "\"ThreadID\":%d, "
                                        "\"ProcessType\":\"%s\", "
                                        "\"Arguments\":{"
                                        "\"fd\":%d, "
                                        "\"Addrlen\":%d,"
                                        "\"SaFamily\":%d,"
                                        "\"Port\":%d,"
                                        "\"Address\":%s} "
                                        "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->acceptArguments.fd,
                            e->acceptArguments.upper_addrlen,
                            e->acceptArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->acceptArguments.fd,
                            e->acceptArguments.upper_addrlen,
                            e->acceptArguments.sa_family,
                            port,
                            ip);
                }
            }
                /**
                 * output to console/shell
                 */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->acceptArguments.fd,
                           e->acceptArguments.upper_addrlen,
                           e->acceptArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->acceptArguments.fd,
                           e->acceptArguments.upper_addrlen,
                           e->acceptArguments.sa_family,
                           port,
                           ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_ACCEPT4: {
            event_type = (char *) "ACCEPT4";
            struct Accept4Event *e = (struct Accept4Event *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->accept4Arguments.sa_family != AF_INET && e->accept4Arguments.sa_family != AF_INET6)
            {
                break;
            }

            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->accept4Arguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->accept4Arguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->accept4Arguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->accept4Arguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                        "\"Timestamp\":%ld,"
                                        "\"EventName\":\"%s\", "
                                        "\"ProcessName\":\"%s\", "
                                        "\"ProcessID\":%d, "
                                        "\"ThreadID\":%d, "
                                        "\"ProcessType\":\"%s\", "
                                        "\"Arguments\":{"
                                        "\"fd\":%d, "
                                        "\"Addrlen\":%d,"
                                        "\"SaFamily\":%d,"
                                        "\"Flags\":%d,"
                                        "\"Port\":%d,"
                                        "\"Address\":%s} "
                                        "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->accept4Arguments.fd,
                            e->accept4Arguments.upper_addrlen,
                            e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->accept4Arguments.fd,
                            e->accept4Arguments.upper_addrlen,
                            e->accept4Arguments.sa_family,
                             e->accept4Arguments.flags,
                            port,
                            ip);
                }
            }
                /**
                 * output to console/shell
                 */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                            "\"Flags\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->accept4Arguments.fd,
                           e->accept4Arguments.upper_addrlen,
                           e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-5d %-39s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->accept4Arguments.fd,
                           e->accept4Arguments.upper_addrlen,
                           e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags,
                           port,
                           ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_BIND: {
            event_type = (char *) "BIND";
            struct BindEvent *e = (struct BindEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->bindArguments.sa_family != AF_INET && e->bindArguments.sa_family != AF_INET6)
            {
                break;
            }
            
            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->bindArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->bindArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->bindArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->bindArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->bindArguments.fd,
                            e->bindArguments.addrlen,
                            e->bindArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->bindArguments.fd,
                            e->bindArguments.addrlen,
                            e->bindArguments.sa_family,
                            port,
                            ip);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"Addrlen\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->bindArguments.fd,
                           e->bindArguments.addrlen,
                           e->bindArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->bindArguments.fd,
                           e->bindArguments.addrlen,
                           e->bindArguments.sa_family,
                           port,
                           ip);
                }
            }
            break;
        }
         case EVENT_NETWORK_GETPEERNAME: {
            event_type = (char *) "GETPEERNAME";
            struct GetPeerNameEvent *e = (struct GetPeerNameEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            if (e->getpeernameArguments.sa_family != AF_INET && e->getpeernameArguments.sa_family != AF_INET6)
            {
                break;
            }
            
            /* declare ip and port for display */
            char ip[INET6_ADDRSTRLEN];
            int port = ntohs(e->getpeernameArguments.s_port);

            /* process IPv4 and IPv6 address */
            switch (e->getpeernameArguments.sa_family) {
                case AF_INET: {
                    inet_ntop(AF_INET, &(e->getpeernameArguments.s_addr), ip, INET_ADDRSTRLEN);
                    break;
                }
                case AF_INET6: {
                    inet_ntop(AF_INET6, &(e->getpeernameArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    break;
                }
                default: {
                    break;
                }
            }

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addr_len\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->getpeernameArguments.fd,
                            e->getpeernameArguments.addr_len,
                            e->getpeernameArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->getpeernameArguments.fd,
                            e->getpeernameArguments.addr_len,
                            e->getpeernameArguments.sa_family,
                            port,
                            ip);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"Addr_len\":%d,"
                           "\"SaFamily\":%d,"
                           "\"Port\":%d,"
                           "\"Address\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->getpeernameArguments.fd,
                           e->getpeernameArguments.addr_len,
                           e->getpeernameArguments.sa_family,
                           port,
                           ip);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->getpeernameArguments.fd,
                           e->getpeernameArguments.addr_len,
                           e->getpeernameArguments.sa_family,
                           port,
                           ip);
                }
            }
            break;
        }
        case EVENT_NETWORK_RECVMMSG: {
            event_type = (char *) "DS_RECVMMSG";
            struct RecvMmsgEvent *e = (struct RecvMmsgEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            //if (e->recvmmsgArguments.sa_family != AF_INET && e->recvmmsgArguments.sa_family != AF_INET6) {
                //break;
            //}

            /* declare ip and port for display */
            //char ip[INET6_ADDRSTRLEN];
            //int port = ntohs(e->recvmmsgArguments.s_port);

            /* process IPv4 and IPv6 address */
            //switch (e->recvmmsgArguments.sa_family) {
                //case AF_INET: {
                    //inet_ntop(AF_INET, &(e->recvmmsgArguments.s_addr), ip, INET_ADDRSTRLEN);
                    //break;
                //}
                //case AF_INET6: {
                    //inet_ntop(AF_INET6, &(e->recvmmsgArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    //break;
                //}
                //default: {
                    //break;
                //}
            //}

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->recvmmsgArguments.fd,
                            e->recvmmsgArguments.flags,
                            e->recvmmsgArguments.vlen);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d  \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->recvmmsgArguments.fd,
                            e->recvmmsgArguments.flags,
                            e->recvmmsgArguments.vlen
                            );
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->recvmmsgArguments.fd,
                            e->recvmmsgArguments.flags,
                            e->recvmmsgArguments.vlen);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d  \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->recvmmsgArguments.fd,
                            e->recvmmsgArguments.flags,
                            e->recvmmsgArguments.vlen
                            );
                }
            }
            break;
        }
        case EVENT_NETWORK_SENDMMSG: {
            event_type = (char *) "SENDMMSG";
            struct SendMmsgEvent *e = (struct SendMmsgEvent *) data;

            /* monitor IPv4, IPv6 sockets only */
            //if (e->sendmmsgArguments.sa_family != AF_INET && e->sendmmsgArguments.sa_family != AF_INET6) {
                //break;
            //}

            /* declare ip and port for display */
            //char ip[INET6_ADDRSTRLEN];
            //int port = ntohs(e->sendmmsgArguments.s_port);

            /* process IPv4 and IPv6 address */
            //switch (e->sendmmsgArguments.sa_family) {
                //case AF_INET: {
                    //inet_ntop(AF_INET, &(e->sendmmsgArguments.s_addr), ip, INET_ADDRSTRLEN);
                    //break;
                //}
                //case AF_INET6: {
                    //inet_ntop(AF_INET6, &(e->sendmmsgArguments.s_addr_v6), ip, INET6_ADDRSTRLEN);
                    //break;
                //}
                //default: {
                    //break;
                //}
            //}

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendmmsgArguments.fd,
                            e->sendmmsgArguments.flags,
                            e->sendmmsgArguments.vlen);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d  \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendmmsgArguments.fd,
                            e->sendmmsgArguments.flags,
                            e->sendmmsgArguments.vlen
                            );
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendmmsgArguments.fd,
                            e->sendmmsgArguments.flags,
                            e->sendmmsgArguments.vlen);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d  \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendmmsgArguments.fd,
                            e->sendmmsgArguments.flags,
                            e->sendmmsgArguments.vlen
                            );
                }
            }
            break;
        }
         case EVENT_NETWORK_SOCKETPAIR: {
            event_type = (char *) "SOCKETPAIR";
            struct SocketPairEvent *e = (struct SocketPairEvent *) data;

            if (my_args_network.if_output_to_file)
            {
                if (my_args_network.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_network, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"family\":%d, "
                                            "\"type\":%d,"
                                            "\"protocol\":%d,"
                                             "\"Sv1\":%d,"
                                              "\"Sv2\":%d,"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->socketpairArguments.family,
                            e->socketpairArguments.type,
                            e->socketpairArguments.protocol,
                            e->socketpairArguments.sv1,
                            e->socketpairArguments.sv2
                            );
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-9d %-9d %-9d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->socketpairArguments.family,
                            e->socketpairArguments.type,
                            e->socketpairArguments.protocol,
                            e->socketpairArguments.sv1,
                            e->socketpairArguments.sv2
                            );
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_network.if_output_as_json)
                {
                    printf("{"
                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"family\":%d, "
                                            "\"type\":%d,"
                                            "\"protocol\":%d,"
                                            "\"Sv1\":%d,"
                                              "\"Sv2\":%d,"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->socketpairArguments.family,
                            e->socketpairArguments.type,
                            e->socketpairArguments.protocol,
                            e->socketpairArguments.sv1,
                            e->socketpairArguments.sv2
                            );
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d  %-9d %-9d %-9d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->socketpairArguments.family,
                            e->socketpairArguments.type,
                            e->socketpairArguments.protocol,
                            e->socketpairArguments.sv1,
                            e->socketpairArguments.sv2
                            );
                }
            }
            break;
        }
    }
    return 0;
}

int test_network(Args args) {
    my_args_network = args;

    if (my_args_network.if_output_to_file) {
        output_network = fopen(my_args_network.output_file.c_str(), "w");
        if (output_network == NULL) {
            fprintf(stderr, "please enter a valid file name/path\n");
            return 1;
        }
    }

    struct ring_buffer *rb = NULL;
    struct network_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = network_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = network_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = network_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_network_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args_network.if_output_as_json) {
        if (my_args_network.if_output_to_file) {
            fprintf(output_network, "%-20s %-10s %-32s %-7s %-7s %10s\n",
                    "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        } else {
            printf("%-20s %-15s %-32s %-7s %-7s %-10s\n",
                   "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        }
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 10);
        if (err == -EINTR) {
            err = 0;
            fclose(output_network);
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            fclose(output_network);
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    network_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
