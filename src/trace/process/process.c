// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "../../include/process.h"
#include "process.skel.h"
#include "../../include/arg_parser.h"
#include "../../include/basic.h"

struct Args my_args_process;

FILE *output_process;

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (my_args_process.if_debug_mode) {
        return vfprintf(stderr, format, args);
    } else {
        return 0;
    }
}

static void handle_signal(int signal) {
    exiting = true;
}

static int handle_process_event(void *ctx, void *data, size_t data_sz) {
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
    if (strcmp("gnome-terminal-", e->comm) == 0 && my_args_process.if_output_to_file == false) {
        return 0;
    }

    char *event_type;

    switch (e->event_type) {
        case EVENT_PROCESS_FORK: {
            event_type = (char *) "FORK";
            struct ForkEvent *e = (struct ForkEvent *) data;
            if (my_args_process.if_output_to_file) {
                if (my_args_process.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_process, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"ParentPID\":%d, "
                                            "\"ParentPName\":\"%s\","
                                            "\"ChildPID\":%d,"
                                            "\"ChildPName\":\"%s\"} "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->forkArguments.parent_pid,
                            e->forkArguments.parent_comm,
                            e->forkArguments.child_pid,
                            e->forkArguments.child_comm);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->forkArguments.parent_pid,
                            e->forkArguments.parent_comm,
                            e->forkArguments.child_pid,
                            e->forkArguments.child_comm);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args_process.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"ParentPID\":%d, "
                           "\"ParentPName\":\"%s\","
                           "\"ChildPID\":%d,"
                           "\"ChildPName\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->forkArguments.parent_pid,
                           e->forkArguments.parent_comm,
                           e->forkArguments.child_pid,
                           e->forkArguments.child_comm);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-10s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->forkArguments.parent_pid,
                           e->forkArguments.parent_comm,
                           e->forkArguments.child_pid,
                           e->forkArguments.child_comm);
                }
            }
            break;
        }
        case EVENT_PROCESS_EXEC: {
            event_type = (char *) "EXEC";
            struct ExecEvent *e = (struct ExecEvent *) data;
            if (my_args_process.if_output_to_file) {
                if (my_args_process.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_process, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"OldPID\":%d, "
                                            "\"PID\":%d,"
                                            "\"Executable\":\"%s\"}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execArguments.old_pid,
                            e->execArguments.pid,
                            e->event.filename);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execArguments.old_pid,
                            e->execArguments.pid,
                            e->event.filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args_process.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"OldPID\":%d, "
                           "\"PID\":%d,"
                           "\"Executable\":\"%s\"}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->execArguments.old_pid,
                           e->execArguments.pid,
                           e->event.filename);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->execArguments.old_pid,
                           e->execArguments.pid,
                           e->event.filename);
                }
            }
            break;
        }
        case EVENT_PROCESS_CLONE: {
            event_type = (char *) "CLONE";
            struct CloneEvent *e = (struct CloneEvent *) data;
            if (my_args_process.if_output_to_file) {
                if (my_args_process.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_process, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"CloneFlags\":%ld, "
                                            "\"NewSP\":%ld,"
                                            "\"TLS\":%ld,"
                                            "\"ParentTidPtr\":%p,"
                                            "\"ChildTidPtr\":%p"
                                            "}} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->cloneArguments.clone_flags,
                            e->cloneArguments.newsp,
                            e->cloneArguments.tls,
                            e->cloneArguments.parent_tidptr,
                            e->cloneArguments.child_tidptr
                            );
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-10p %-10p \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->cloneArguments.clone_flags,
                            e->cloneArguments.newsp,
                            e->cloneArguments.tls,
                            e->cloneArguments.parent_tidptr,
                            e->cloneArguments.child_tidptr);
                }
            }
            /**
             * output to console/shell
             */
            else {
                if (my_args_process.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"CloneFlags\":%ld, "
                           "\"NewSP\":%ld,"
                           "\"TLS\":%ld,"
                           "\"ParentTidPtr\":%p,"
                           "\"ChildTidPtr\":%p"
                           "}} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->cloneArguments.clone_flags,
                           e->cloneArguments.newsp,
                           e->cloneArguments.tls,
                           e->cloneArguments.parent_tidptr,
                           e->cloneArguments.child_tidptr);
                }
                    // raw output
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-10p %-10p \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->cloneArguments.clone_flags,
                           e->cloneArguments.newsp,
                           e->cloneArguments.tls,
                           e->cloneArguments.parent_tidptr,
                           e->cloneArguments.child_tidptr);
                }
            }
            break;
        }
        case EVENT_PROCESS_EXIT: {
            event_type = (char *) "EXIT";
            struct ExitEvent *e = (struct ExitEvent *) data;
            if (my_args_process.if_output_to_file) {
                if (my_args_process.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_process, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"PID\":%d, "
                                            "\"ExitPName\":%s,"
                                            "\"Priority\":%d}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->exitArguments.pid,
                            e->exitArguments.comm,
                            e->exitArguments.prio);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->exitArguments.pid,
                            e->exitArguments.comm,
                            e->exitArguments.prio);
                }
            }
            /**
             * output to console/shell
             */
            else {
                if (my_args_process.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"PID\":%d, "
                           "\"ExitPName\":%s,"
                           "\"Priority\":%d}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->exitArguments.pid,
                           e->exitArguments.comm,
                           e->exitArguments.prio);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->exitArguments.pid,
                           e->exitArguments.comm,
                           e->exitArguments.prio);
                }
            }
            break;
        }
    }

    return 0;
}

int test_process(Args args) {
    my_args_process = args;

    if (my_args_process.if_output_to_file) {
        output_process = fopen(my_args_process.output_file.c_str(), "w");
        if (output_process == NULL) {
            fprintf(stderr, "please enter a valid file name/path\n");
            return 1;
        }
    }

    struct ring_buffer *rb = NULL;
    struct process_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = process_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = process_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = process_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_process_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args_process.if_output_as_json) {
        if (my_args_process.if_output_to_file) {
            fprintf(output_process, "%-20s %-10s %-32s %-7s %-7s %10s\n",
                    "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        } else {
            printf("%-20s %-10s %-32s %-7s %-7s %10s\n",
                   "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        }
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 10);
        if (err == -EINTR) {
            err = 0;
            fclose(output_process);
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            fclose(output_process);
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    process_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}