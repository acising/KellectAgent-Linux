// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
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
                                            "\"Exit_code\":%d, "
                                            "\"PID\":%d, "
                                            "\"ExitPName\":%s,"
                                            "\"Priority\":%d}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->exitArguments.exit_code,
                            e->exitArguments.pid,
                            e->exitArguments.comm,
                            e->exitArguments.prio);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-5d %-7d %-20s %-7d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->exitArguments.exit_code,
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
                           "\"Exit_code\":%d, "
                           "\"PID\":%d, "
                           "\"ExitPName\":%s,"
                           "\"Priority\":%d}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->exitArguments.exit_code,
                           e->exitArguments.pid,
                           e->exitArguments.comm,
                           e->exitArguments.prio);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-5d %-7d %-20s %-7d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->exitArguments.exit_code,
                           e->exitArguments.pid,
                           e->exitArguments.comm,
                           e->exitArguments.prio);
                }
            }
            break;
        }
        case EVENT_PROCESS_PIPE: {
            event_type = (char *) "PIPE";
            struct PipeEvent *e = (struct PipeEvent *) data;
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
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->pipeArguments.f1,
                            e->pipeArguments.f2);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pipeArguments.f1,
                            e->pipeArguments.f2);
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
                            "\"F1\":%d, "
                            "\"F2\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->pipeArguments.f1,
                            e->pipeArguments.f2);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->pipeArguments.f1,
                            e->pipeArguments.f2);
                }
            }
            break;
        }
        case EVENT_PROCESS_PIPE2: {
            event_type = (char *) "PIPE2";
            struct Pipe2Event *e = (struct Pipe2Event *) data;
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
                                           "\"Flags\":%d, "
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->pipe2Arguments.flags,e->pipe2Arguments.f1,
                            e->pipe2Arguments.f2);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pipe2Arguments.flags,e->pipe2Arguments.f1,
                            e->pipe2Arguments.f2);
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
                            "\"Flags\":%d, "
                             "\"F1\":%d, "
                            "\"F2\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->pipe2Arguments.flags,e->pipe2Arguments.f1,
                            e->pipe2Arguments.f2);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d  \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->pipe2Arguments.flags,e->pipe2Arguments.f1,
                            e->pipe2Arguments.f2);
                }
            }
            break;
        }
        case EVENT_PROCESS_KILL: {
            event_type = (char *) "KILL";
            struct KillEvent *e = (struct KillEvent *) data;
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
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->killArguments.pid,
                            e->killArguments.sig);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->killArguments.pid,
                            e->killArguments.sig);
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
                            "\"pid\":%d, "
                            "\"sig\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                             e->killArguments.pid,
                            e->killArguments.sig);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                             e->killArguments.pid,
                            e->killArguments.sig);
                }
            }
            break;
        }
         case EVENT_PROCESS_CLONE3: {
            event_type = (char *) "CLONE3";
            struct Clone3Event *e = (struct Clone3Event *) data;
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
                                            "\"size\":%d,"
                                            "}} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->clone3Arguments.size
                            );
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s  %-7d   \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->clone3Arguments.size
                            );
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
                           "\"size\":%d,"
                           "}} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->clone3Arguments.size
                            );
                }
                    // raw output
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s  %-7d   \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->clone3Arguments.size
                            );
                }
            }
            break;
        }
        case EVENT_PROCESS_EXECVE: {
            event_type = (char *) "EXECVE";
            struct ExecveEvent *e = (struct ExecveEvent *) data;
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
                                            "\"Filename\":\"%s\","
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->execveArguments.filename);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s  \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execveArguments.filename);
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
                           "\"Filename\":\"%s\","
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->execveArguments.filename);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-10s  \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->execveArguments.filename);
                }
            }
            break;
        }
         case EVENT_PROCESS_EXECVEAT: {
            event_type = (char *) "EXECVEAT";
            struct ExecveatEvent *e = (struct ExecveatEvent *) data;
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
                                            "\"FD\":%d, "
                                            "\"Filename\":\"%s\","
                                            "\"flags\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags);
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
                           "\"FD\":%d, "
                           "\"Filename\":\"%s\","
                           "\"flags\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags);
                }
            }
            break;
        }
        case EVENT_PROCESS_EXIT_GROUP: {
            event_type = (char *) "EXIT_GROUP";
            struct Exit_groupEvent *e = (struct Exit_groupEvent *) data;
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
                                            "\"Code\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->exitgroupArguments.exit_code);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->exitgroupArguments.exit_code);
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
                           "\"Code\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->exitgroupArguments.exit_code);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d  \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->exitgroupArguments.exit_code);
                }
            }
            break;
        }
                case EVENT_PROCESS_PTRACE: {
            event_type = (char *) "PTRACE";
            struct PtraceEvent *e = (struct PtraceEvent *) data;
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
                                            "\"Request\":%ld, "
                                            "\"Pid\":%ld, "
                                            "\"Addr\":%ld, "
                                            "\"Data\":%ld, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->ptraceArguments.request,
                            e->ptraceArguments.pid,
                            e->ptraceArguments.addr,
                            e->ptraceArguments.data);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-7ld \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->ptraceArguments.request,
                            e->ptraceArguments.pid,
                            e->ptraceArguments.addr,
                            e->ptraceArguments.data);
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
                            "\"Request\":%ld, "
                            "\"Pid\":%ld, "
                            "\"Addr\":%ld, "
                            "\"Data\":%ld, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                          e->ptraceArguments.request,
                            e->ptraceArguments.pid,
                            e->ptraceArguments.addr,
                            e->ptraceArguments.data);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-7ld  \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                          e->ptraceArguments.request,
                            e->ptraceArguments.pid,
                            e->ptraceArguments.addr,
                            e->ptraceArguments.data);
                }
            }
            break;
        }
        case EVENT_PROCESS_TGKILL: {
            event_type = (char *) "TGKILL";
            struct TgkillEvent *e = (struct TgkillEvent *) data;
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
                                             "\"tgid\":%d, "
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->tgkillArguments.tgid,
                            e->tgkillArguments.pid,
                            e->tgkillArguments.sig);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                           e->tgkillArguments.tgid,
                            e->tgkillArguments.pid,
                            e->tgkillArguments.sig);
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
                            "\"tgid\":%d, "
                            "\"pid\":%d, "
                            "\"sig\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->tgkillArguments.tgid,
                            e->tgkillArguments.pid,
                            e->tgkillArguments.sig);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d  %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                             e->tgkillArguments.tgid,
                            e->tgkillArguments.pid,
                            e->tgkillArguments.sig);
                }
            }
            break;
        }
        case EVENT_PROCESS_TKILL: {
            event_type = (char *) "TKILL";
            struct TkillEvent *e = (struct TkillEvent *) data;
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
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->tkillArguments.pid,
                            e->tkillArguments.sig);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->tkillArguments.pid,
                            e->tkillArguments.sig);
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
                            "\"pid\":%d, "
                            "\"sig\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->tkillArguments.pid,
                            e->tkillArguments.sig);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d  \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->tkillArguments.pid,
                            e->tkillArguments.sig);
                }
            }
            break;
        }
        case EVENT_PROCESS_VFORK: {
            event_type = (char *) "VFORK";
            struct VforkEvent *e = (struct VforkEvent *) data;
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
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type);
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
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type);
                }
            }
            break;
        }
        case EVENT_PROCESS_MMAP: {
            event_type = (char *) "MMAP";
            struct MmapEvent *e = (struct MmapEvent *) data;
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
                                            "\"Addr\":%ld, "
                                            "\"Len\":%ld, "
                                            "\"Prot\":%ld, "
                                            "\"Flags\":%ld, "
                                            "\"Fd\":%ld, "
                                            "\"Off\":%ld, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->mmapArguments.addr,
                            e->mmapArguments.len,
                            e->mmapArguments.prot,
                            e->mmapArguments.flags,
                            e->mmapArguments.fd,
                            e->mmapArguments.off);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-7ld %-7ld %-7ld \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->mmapArguments.addr,
                            e->mmapArguments.len,
                            e->mmapArguments.prot,
                            e->mmapArguments.flags,
                            e->mmapArguments.fd,
                            e->mmapArguments.off);
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
                             "\"Addr\":%ld, "
                            "\"Len\":%ld, "
                             "\"Prot\":%ld, "
                            "\"Flags\":%ld, "
                            "\"Fd\":%ld, "
                             "\"Off\":%ld, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->mmapArguments.addr,
                            e->mmapArguments.len,
                            e->mmapArguments.prot,
                            e->mmapArguments.flags,
                            e->mmapArguments.fd,
                            e->mmapArguments.off);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-7ld %-7ld %-7ld  \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->mmapArguments.addr,
                            e->mmapArguments.len,
                            e->mmapArguments.prot,
                            e->mmapArguments.flags,
                            e->mmapArguments.fd,
                            e->mmapArguments.off);
                }
            }
            break;
        }
        case EVENT_PROCESS_MPROTECT: {
            event_type = (char *) "MPROTECT";
            struct MprotectEvent *e = (struct MprotectEvent *) data;
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
                                            "\"Addr\":%ld, "
                                            "\"Len\":%zu, "
                                            "\"Prot\":%ld, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->mprotectArguments.start,
                            e->mprotectArguments.len,
                            e->mprotectArguments.prot);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7zu %-7ld \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                           e->mprotectArguments.start,
                            e->mprotectArguments.len,
                            e->mprotectArguments.prot);
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
                            "\"Addr\":%ld, "
                            "\"Len\":%zu, "
                             "\"Prot\":%ld, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->mprotectArguments.start,
                            e->mprotectArguments.len,
                            e->mprotectArguments.prot);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7zu %-7ld \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->mprotectArguments.start,
                            e->mprotectArguments.len,
                            e->mprotectArguments.prot);
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
