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
                                            "\"SaData\":%s} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->connectArguments.fd,
                            e->connectArguments.addrlen,
                            e->connectArguments.sa_family,
                            e->connectArguments.sa_data);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-25s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->connectArguments.fd,
                            e->connectArguments.addrlen,
                            e->connectArguments.sa_family,
                            e->connectArguments.sa_data);
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
                           "\"SaData\":%s} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->connectArguments.fd,
                           e->connectArguments.addrlen,
                           e->connectArguments.sa_family,
                           e->connectArguments.sa_data);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-25s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->connectArguments.fd,
                           e->connectArguments.addrlen,
                           e->connectArguments.sa_family,
                           e->connectArguments.sa_data);
                }
            }
            break;
        }
        case EVENT_NETWORK_SOCKET: {
            event_type = (char *) "SOCKET";
            struct SocketEvent *e = (struct SocketEvent *) data;
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
                                            "\"SocketFamily\":%d, "
                                            "\"SocketType\":%d,"
                                            "\"Protocol\":%d}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->socketArguments.family,
                            e->socketArguments.type,
                            e->socketArguments.protocol);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->socketArguments.family,
                            e->socketArguments.type,
                            e->socketArguments.protocol);
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
                           "\"SocketFamily\":%d, "
                           "\"SocketType\":%d,"
                           "\"Protocol\":%d}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->socketArguments.family,
                           e->socketArguments.type,
                           e->socketArguments.protocol);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->socketArguments.family,
                           e->socketArguments.type,
                           e->socketArguments.protocol);
                }
            }
            break;
        }
        case EVENT_NETWORK_TCP_IPV4: {
            event_type = (char *) "TCP_IPv4";
            struct TcpIpv4ConnectEvent *e = (struct TcpIpv4ConnectEvent *) data;

            uint32_t s_addr = e->tcpIpv4ConnectArguments.s_addr;
            uint8_t bytes[4];
            bytes[0] = s_addr & 0xFF;
            bytes[1] = (s_addr >> 8) & 0xFF;
            bytes[2] = (s_addr >> 16) & 0xFF;
            bytes[3] = (s_addr >> 24) & 0xFF;

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
                                            "\"AddrLen\":%d, "
                                            "\"SinFamily\":%hu,"
                                            "\"SinPort\":%hu,"
                                            "\"SAddr\":%u,"
                                            "\"IPv4Addr\":%u.%u.%u.%u} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->tcpIpv4ConnectArguments.addr_len,
                            e->tcpIpv4ConnectArguments.sin_family,
                            e->tcpIpv4ConnectArguments.sin_port,
                            e->tcpIpv4ConnectArguments.s_addr,
                            bytes[0], bytes[1], bytes[2], bytes[3]);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7hu %-7hu %-15u %u.%u.%u.%u\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->tcpIpv4ConnectArguments.addr_len,
                            e->tcpIpv4ConnectArguments.sin_family,
                            e->tcpIpv4ConnectArguments.sin_port,
                            e->tcpIpv4ConnectArguments.s_addr,
                            bytes[0], bytes[1], bytes[2], bytes[3]);
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
                           "\"AddrLen\":%d, "
                           "\"SinFamily\":%hu,"
                           "\"SinPort\":%hu,"
                           "\"SAddr\":%u,"
                           "\"IPv4Addr\":%u.%u.%u.%u} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->tcpIpv4ConnectArguments.addr_len,
                           e->tcpIpv4ConnectArguments.sin_family,
                           e->tcpIpv4ConnectArguments.sin_port,
                           e->tcpIpv4ConnectArguments.s_addr,
                           bytes[0], bytes[1], bytes[2], bytes[3]);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7hu %-7hu %-15u %u.%u.%u.%u\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->tcpIpv4ConnectArguments.addr_len,
                           e->tcpIpv4ConnectArguments.sin_family,
                           e->tcpIpv4ConnectArguments.sin_port,
                           e->tcpIpv4ConnectArguments.s_addr,
                           bytes[0], bytes[1], bytes[2], bytes[3]);
                }
            }
            break;
        }
        case EVENT_NETWORK_SEND: {
            event_type = (char *) "PKG_SEND";
            struct SendEvent *e = (struct SendEvent *) data;

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
                                            "\"Len\":%d, "
                                            "\"RC\":%d,"
                                            "\"FileName\":%s}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendArguments.len,
                            e->sendArguments.rc,
                            e->event.filename);
                }
                else
                {
                    fprintf(output_network, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->sendArguments.len,
                            e->sendArguments.rc,
                            e->event.filename);
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
                           "\"Len\":%d, "
                           "\"RC\":%d,"
                           "\"FileName\":%s}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->sendArguments.len,
                           e->sendArguments.rc,
                           e->event.filename);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->sendArguments.len,
                           e->sendArguments.rc,
                           e->event.filename);
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