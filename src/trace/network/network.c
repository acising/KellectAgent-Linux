// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
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


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // return vfprintf(stderr, format, args);
    return 0;
}

static volatile bool exiting = false;

static void handle_signal(int signal)
{
    exiting = true;
}

struct Args my_args_network;

FILE *file_network;

static int handle_process_event(void *ctx, void *data, size_t data_sz)
{
    const struct Event *e = (struct Event *)data;
    char *process_type;
    if (e->is_process)
    {
        process_type = (char *)"process";
    }
    else
    {
        process_type = (char *)"thread";
    }

    if (strcmp("kellect", e->comm) == 0)
    {
        return 0;
    }
    if (strcmp("gnome-terminal-", e->comm) == 0)
    {
        return 0;
    }

    char *event_type;

    switch (e->event_type)
    {
        // case EVENT_CONNECT:
        // {
        //     event_type = (char *)"CONNECT";
        //     struct ConnectEvent *e = (struct ConnectEvent *)data;

        //     printf("%-20ld %-15s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-25s\n",
        //         getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, 
        //         e->connectArguments.fd, e->connectArguments.addrlen, e->connectArguments.sa_family,
        //         e->connectArguments.sa_data);

        //     break;
        // }
        // case EVENT_SOCKET:
        // {
        //     event_type = (char *)"SOCKET";
        //     struct SocketEvent *e = (struct SocketEvent *)data;

        //     printf("\033[32m%-20ld %-15s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\033[0m\n",
        //         getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, 
        //         e->socketArguments.family, e->socketArguments.type, e->socketArguments.protocol);

        //     break;
        // }
        // case EVENT_TCP_IPV4:
        // {
        //     event_type = (char *)"TCP_CONNECT";
        //     struct TcpIpv4ConnectEvent *e = (struct TcpIpv4ConnectEvent *)data;
            
        //     uint32_t s_addr = e->tcpIpv4ConnectArguments.s_addr;
        //     uint8_t bytes[4];
        //     bytes[0] = s_addr & 0xFF;
        //     bytes[1] = (s_addr >> 8) & 0xFF;
        //     bytes[2] = (s_addr >> 16) & 0xFF;
        //     bytes[3] = (s_addr >> 24) & 0xFF;

        //     // bytes[0] = (s_addr >> 24) & 0xFF;
        //     // bytes[1] = (s_addr >> 16) & 0xFF;
        //     // bytes[2] = (s_addr >> 8) & 0xFF;
        //     // bytes[3] = s_addr & 0xFF;
        //     // printf("IP address: %u.%u.%u.%u\n", bytes[0], bytes[1], bytes[2], bytes[3]);

        //     printf("%-20ld %-15s %-32s %-7d %-7d %-10s %-10s %-7d %-7hu %-7hu %-15u %u.%u.%u.%u\n",
        //         getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, 
        //         "---->", e->tcpIpv4ConnectArguments.addr_len, e->tcpIpv4ConnectArguments.sin_family,
        //         e->tcpIpv4ConnectArguments.sin_port, e->tcpIpv4ConnectArguments.s_addr,
        //         bytes[0], bytes[1], bytes[2], bytes[3]);
            
        //     break;
        // }
        case EVENT_SEND:
        {
            event_type = (char *)"PKG_SEND";
            struct SendEvent *e = (struct SendEvent *)data;
            
            printf("%-20ld %-15s %-32s %-7d %-7d %-10s %-10s %-7d %-7d %-20s\n",
                getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, 
                "---->", e->sendArguments.len, e->sendArguments.rc, e->event.filename);
            
            break;
        }
    }

    return 0;
}

int test_network(Args args)
{
    my_args_network = args;

    if (my_args_network.if_output_to_file)
    {
        file_network = fopen(my_args_network.output_file.c_str(), "w");
        if (file_network == NULL)
        {
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
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = network_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = network_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_process_event, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args_network.if_output_as_json)
    {
        if (my_args_network.if_output_to_file)
        {
            fprintf(file_network, "%-15s %-5s %-64s %-7s %-7s %5s\n",
                    "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        }
        else
        {
            printf("%-20s %-15s %-32s %-7s %-7s %-10s\n",
                   "TimeStamp", "EventName", "COMM", "PID", "PPID", "TYPE");
        }
    }

    while (!exiting)
    {
        err = ring_buffer__poll(rb, 10);
        if (err == -EINTR)
        {
            err = 0;
            fclose(file_network);
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            fclose(file_network);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    network_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}