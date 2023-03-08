// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "../../include/fork.h"
#include "fork.skel.h"
#include "../../include/arg_parser.h"
#include "../../include/basic.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    //return vfprintf(stderr, format, args);
    return 0;
}

static volatile bool exiting = false;

static void handle_signal(int signal)
{
    exiting = true;
}

struct Args my_args_fork;

FILE * file_fork;

static int handle_process_event(void *ctx, void *data, size_t data_sz)
{
    const struct Event *e = (struct Event *)data;
    char* process_type;
    if(e->is_process){
        process_type = (char*)"process";
    }else {
        process_type = (char*)"thread";
    }

    if(strcmp("kellect", e->comm) == 0) {
        return 0;
    }
    if(strcmp("gnome-terminal-", e->comm) == 0) {
        return 0;
    }

    char* event_type;

    switch (e->event_type){
        case EVENT_FORK: {
            event_type = (char *) "FORK";break;
        }
        case EVENT_EXEC: event_type = (char*)"EXEC"; break;
        case EVENT_EXIT: event_type = (char*)"EXIT"; break;
        case EVENT_OPEN: {
            event_type = (char*)"OPEN";
            break;
        }
        case EVENT_CLOSE: event_type = (char*)"CLOSE"; break;
        case EVENT_READ: event_type = (char*)"READ"; break;
        case EVENT_WRITE: event_type = (char*)"WRITE"; break;
    }

    if(my_args_fork.if_output_to_file){
        if(my_args_fork.if_output_as_json){
            // output the record as json
            fprintf(file_fork,"{"
                         "\"Timestamp\":%ld,"
                         "\"EventName\":\"%s\", "
                         "\"ProcessName\":\"%s\", "
                         "\"ProcessID\":%d, "
                         "\"ThreadID\":%d, "
                         "\"ProcessType\":\"%s\", "
                         "\"Arguments\":{"
                         "\"UserModeTime\":%llu, "
                         "\"KernelModeTime\":%llu,"
                         "\"VContextSwitch\":%lu,"
                         "\"IVContextSwitch\":%lu} } \n",
                    getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->comm, e->pid, e->ppid, process_type,
                    e->user_mode_time, e->kernel_mode_time, e->voluntary_context_switch_count, e->involuntary_context_switch_count);
        }else{
            fprintf(file_fork,"%-20ld %-5s %-64s %-7d %-7d %-5s %-20s \n",
                    getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->comm, e->pid, e->ppid, process_type, e->filename);
        }
    }else{
        if(my_args_fork.if_output_as_json){
            printf("%-20ld %-5s %-64s %-7d %-7d %-5s %-20s \n",
                   getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->comm, e->pid, e->ppid, process_type, e->filename);
        }else{
            printf("%-20ld %-5s %-64s %-7d %-7d %-5s %-20s \n",
                   getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->comm, e->pid, e->ppid, process_type, e->filename);
        }
    }
    return 0;
}


int test_process(Args args)
{
    my_args_fork = args;

    if(my_args_fork.if_output_to_file){
        file_fork = fopen(my_args_fork.output_file.c_str(),"w");
        if(file_fork == NULL){
            fprintf(stderr, "please enter a valid file name/path\n");
            return 1;
        }
    }

    struct ring_buffer *rb = NULL;
    struct fork_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = fork_bpf__open();
    if(!skel){
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = fork_bpf__load(skel);
    if(err){
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = fork_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_process_event, NULL, NULL);
    if(!rb){
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /**
     * if the output format is json, do not print the title.
     */
    if(!my_args_fork.if_output_as_json){
        if(my_args_fork.if_output_to_file){
            fprintf(file_fork, "%-15s %-5s %-64s %-7s %-7s %5s\n",
                    "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        }else{
            printf("%-15s %-5s %-64s %-7s %-7s %5s\n",
                   "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        }
    }

    while(!exiting) {
        err = ring_buffer__poll(rb, 10);
        if(err == -EINTR){
            err = 0;
            fclose(file_fork);
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            fclose(file_fork);
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    fork_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}