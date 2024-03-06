// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Created by zhuzhiling on 9/7/22.
//
#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "../../include/all.h"
#include "../../include/arg_parser.h"
#include "../../include/basic.h"
#include "all.skel.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct Args my_args;

FILE * output_all;

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (my_args.if_debug_mode) {
        return vfprintf(stderr, format, args);
    } else {
        return 0;
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
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
    if (strcmp("gnome-terminal-", e->comm) == 0 && my_args.if_output_to_file == false) {
        return 0;
    }

    char *event_type;

    switch (e->event_type) {
        /// Kellect v1.0
        case EVENT_FILE_OPEN: {
            event_type = (char *) "OPEN_FILE";
            struct OpenFileEvent *e = (struct OpenFileEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"OpenDFD\":%d, "
                                         "\"OpenFilename\":\"%s\","
                                         "\"OpenFlags\":%d,"
                                         "\"OpenMode\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->openFileArguments.open_dfd,
                            e->openFileArguments.open_filename,
                            e->openFileArguments.open_flags,
                            e->openFileArguments.open_mode);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"OpenDFD\":%d, "
                                         "\"OpenFilename\":\"%s\","
                                         "\"OpenFlags\":%d,"
                                         "\"OpenMode\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->openFileArguments.open_dfd,
                            e->openFileArguments.open_filename,
                            e->openFileArguments.open_flags,
                            e->openFileArguments.open_mode);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->openFileArguments.open_dfd,
                            e->openFileArguments.open_filename,
                            e->openFileArguments.open_flags,
                            e->openFileArguments.open_mode);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"OpenDFD\":%d, "
                           "\"OpenFilename\":\"%s\","
                           "\"OpenFlags\":%d,"
                           "\"OpenMode\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->openFileArguments.open_dfd,
                           e->openFileArguments.open_filename,
                           e->openFileArguments.open_flags,
                           e->openFileArguments.open_mode);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"OpenDFD\":%d, "
                                         "\"OpenFilename\":\"%s\","
                                         "\"OpenFlags\":%d,"
                                         "\"OpenMode\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->openFileArguments.open_dfd,
                            e->openFileArguments.open_filename,
                            e->openFileArguments.open_flags,
                            e->openFileArguments.open_mode);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->openFileArguments.open_dfd,
                           e->openFileArguments.open_filename,
                           e->openFileArguments.open_flags,
                           e->openFileArguments.open_mode);
                }
            }
            break;
        }
        case EVENT_FILE_DELETE: {
            event_type = (char *) "DELETE";
            struct DeleteEvent *e = (struct DeleteEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"DeleteDFD\":%d, "
                                         "\"DeleteFilename\":\"%s\","
                                         "\"OpenFlags\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->deleteArguments.delete_dfd,
                            e->deleteArguments.delete_pathname,
                            e->deleteArguments.delete_flag);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"DeleteDFD\":%d, "
                                         "\"DeleteFilename\":\"%s\","
                                         "\"OpenFlags\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->deleteArguments.delete_dfd,
                            e->deleteArguments.delete_pathname,
                            e->deleteArguments.delete_flag);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->deleteArguments.delete_dfd,
                            e->deleteArguments.delete_pathname,
                            e->deleteArguments.delete_flag);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"DeleteDFD\":%d, "
                           "\"DeleteFilename\":\"%s\","
                           "\"OpenFlags\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->deleteArguments.delete_dfd,
                           e->deleteArguments.delete_pathname,
                           e->deleteArguments.delete_flag);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"DeleteDFD\":%d, "
                                         "\"DeleteFilename\":\"%s\","
                                         "\"OpenFlags\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->deleteArguments.delete_dfd,
                            e->deleteArguments.delete_pathname,
                            e->deleteArguments.delete_flag);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->deleteArguments.delete_dfd,
                           e->deleteArguments.delete_pathname,
                           e->deleteArguments.delete_flag);
                }
            }
            break;
        }
        case EVENT_FILE_RENAMEAT_2: {
            event_type = (char *) "RENAMEAT2";
            struct Renameat2Event *e = (struct Renameat2Event *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"OldDFD\":%d, "
                                         "\"OldFilename\":\"%s\","
                                         "\"NewDFD\":%d,"
                                         "\"NewFilename\":\"%s\","
                                         "\"RenameFlags\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameat2Arguments.rename_olddfd,
                            e->renameat2Arguments.rename_oldname,
                            e->renameat2Arguments.rename_newdfd,
                            e->renameat2Arguments.rename_newname,
                            e->renameat2Arguments.rename_flags);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"OldDFD\":%d, "
                                         "\"OldFilename\":\"%s\","
                                         "\"NewDFD\":%d,"
                                         "\"NewFilename\":\"%s\","
                                         "\"RenameFlags\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->renameat2Arguments.rename_olddfd,
                            e->renameat2Arguments.rename_oldname,
                            e->renameat2Arguments.rename_newdfd,
                            e->renameat2Arguments.rename_newname,
                            e->renameat2Arguments.rename_flags);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-20s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameat2Arguments.rename_olddfd,
                            e->renameat2Arguments.rename_oldname,
                            e->renameat2Arguments.rename_newdfd,
                            e->renameat2Arguments.rename_newname,
                            e->renameat2Arguments.rename_flags);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"OldDFD\":%d, "
                           "\"OldFilename\":\"%s\","
                           "\"NewDFD\":%d,"
                           "\"NewFilename\":\"%s\","
                           "\"RenameFlags\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->renameat2Arguments.rename_olddfd,
                           e->renameat2Arguments.rename_oldname,
                           e->renameat2Arguments.rename_newdfd,
                           e->renameat2Arguments.rename_newname,
                           e->renameat2Arguments.rename_flags);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"OldDFD\":%d, "
                                         "\"OldFilename\":\"%s\","
                                         "\"NewDFD\":%d,"
                                         "\"NewFilename\":\"%s\","
                                         "\"RenameFlags\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->renameat2Arguments.rename_olddfd,
                            e->renameat2Arguments.rename_oldname,
                            e->renameat2Arguments.rename_newdfd,
                            e->renameat2Arguments.rename_newname,
                            e->renameat2Arguments.rename_flags);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-20s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->renameat2Arguments.rename_olddfd,
                           e->renameat2Arguments.rename_oldname,
                           e->renameat2Arguments.rename_newdfd,
                           e->renameat2Arguments.rename_newname,
                           e->renameat2Arguments.rename_flags);
                }
            }
            break;
        }
        case EVENT_FILE_CHANGE_MODE: {
            event_type = (char *) "CHANGE_MODE";
            struct ChangeModeEvent *e = (struct ChangeModeEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"ChangeDFD\":%d, "
                                         "\"ChangeMode\":%d,"
                                         "\"ChangeFilename\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->changeModeArguments.chmod_dfd,
                            e->changeModeArguments.chmod_mode,
                            e->changeModeArguments.chmod_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ChangeDFD\":%d, "
                                         "\"ChangeMode\":%d,"
                                         "\"ChangeFilename\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->changeModeArguments.chmod_dfd,
                            e->changeModeArguments.chmod_mode,
                            e->changeModeArguments.chmod_filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->changeModeArguments.chmod_dfd,
                            e->changeModeArguments.chmod_mode,
                            e->changeModeArguments.chmod_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"ChangeDFD\":%d, "
                           "\"ChangeMode\":%d,"
                           "\"ChangeFilename\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->changeModeArguments.chmod_dfd,
                           e->changeModeArguments.chmod_mode,
                           e->changeModeArguments.chmod_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ChangeDFD\":%d, "
                                         "\"ChangeMode\":%d,"
                                         "\"ChangeFilename\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->changeModeArguments.chmod_dfd,
                            e->changeModeArguments.chmod_mode,
                            e->changeModeArguments.chmod_filename);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->changeModeArguments.chmod_dfd,
                           e->changeModeArguments.chmod_mode,
                           e->changeModeArguments.chmod_filename);
                }
            }
            break;
        }
        case EVENT_FILE_GET_MODE: {
            event_type = (char *) "GET_MODE";
            struct GetModeEvent *e = (struct GetModeEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"GetMode\":%d, "
                                         "\"GetUID\":%d,"
                                         "\"GetPID\":%d,"
                                         "\"GetFilename\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->getModeArguments.stat_mode,
                            e->getModeArguments.stat_uid,
                            e->getModeArguments.stat_gid,
                            e->getModeArguments.stat_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"GetMode\":%d, "
                                         "\"GetUID\":%d,"
                                         "\"GetPID\":%d,"
                                         "\"GetFilename\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->getModeArguments.stat_mode,
                            e->getModeArguments.stat_uid,
                            e->getModeArguments.stat_gid,
                            e->getModeArguments.stat_filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->getModeArguments.stat_mode,
                            e->getModeArguments.stat_uid,
                            e->getModeArguments.stat_gid,
                            e->getModeArguments.stat_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"GetMode\":%d, "
                           "\"GetUID\":%d,"
                           "\"GetPID\":%d,"
                           "\"GetFilename\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->getModeArguments.stat_mode,
                           e->getModeArguments.stat_uid,
                           e->getModeArguments.stat_gid,
                           e->getModeArguments.stat_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"GetMode\":%d, "
                                         "\"GetUID\":%d,"
                                         "\"GetPID\":%d,"
                                         "\"GetFilename\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->getModeArguments.stat_mode,
                            e->getModeArguments.stat_uid,
                            e->getModeArguments.stat_gid,
                            e->getModeArguments.stat_filename);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->getModeArguments.stat_mode,
                           e->getModeArguments.stat_uid,
                           e->getModeArguments.stat_gid,
                           e->getModeArguments.stat_filename);
                }
            }
            break;
        }
        case EVENT_FILE_CHANGE_DIR: {
            event_type = (char *) "CHANGE_DIR";
            struct ChangeDirEvent *e = (struct ChangeDirEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"ChangeDirname\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->changeDirArguments.chdir_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ChangeDirname\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->changeDirArguments.chdir_filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->changeDirArguments.chdir_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"ChangeDirname\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->changeDirArguments.chdir_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ChangeDirname\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->changeDirArguments.chdir_filename);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->changeDirArguments.chdir_filename);
                }
            }
            break;
        }
        case EVENT_FILE_MAKE_DIR: {
            event_type = (char *) "MAKE_DIR";
            struct MakeDirEvent *e = (struct MakeDirEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"DirMode\":%d, "
                                         "\"Dirname\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->makeDirArguments.mkdir_mode,
                            e->makeDirArguments.mkdir_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"DirMode\":%d, "
                                         "\"Dirname\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->makeDirArguments.mkdir_mode,
                            e->makeDirArguments.mkdir_filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,e->event.ppid, process_type,
                            e->makeDirArguments.mkdir_mode,
                            e->makeDirArguments.mkdir_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"DirMode\":%d, "
                           "\"Dirname\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->makeDirArguments.mkdir_mode,
                           e->makeDirArguments.mkdir_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"DirMode\":%d, "
                                         "\"Dirname\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->makeDirArguments.mkdir_mode,
                            e->makeDirArguments.mkdir_filename);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->makeDirArguments.mkdir_mode,
                           e->makeDirArguments.mkdir_filename);
                }
            }
            break;
        }
        case EVENT_FILE_REMOVE_DIR: {
            event_type = (char *) "REMOVE_DIR";
            struct RemoveDirEvent *e = (struct RemoveDirEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"Dirname\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->removeDirArguments.rmdir_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"Dirname\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->removeDirArguments.rmdir_filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->removeDirArguments.rmdir_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Dirname\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->removeDirArguments.rmdir_filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"Dirname\":\"%s\"}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->removeDirArguments.rmdir_filename);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->removeDirArguments.rmdir_filename);
                }
            }
            break;
        }
        case EVENT_FILE_READ_FILE: {
            event_type = (char *) "READ_FILE";
            struct ReadFileEvent *e = (struct ReadFileEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"Inode\":%lld, "
                                         "\"FileUser\":%d, "
                                         "\"FileMode\":%d, "
                                         "\"ReadBytes\":%lld, "
                                         "\"FileName\":\"%s\","
                                         "} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->event.filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"Inode\":%lld, "
                                         "\"FileUser\":%d, "
                                         "\"FileMode\":%d, "
                                         "\"ReadBytes\":%lld, "
                                         "\"FileName\":\"%s\"}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->event.filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->event.filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf( "{"
                            "\"Timestamp\":%ld,"
                            "\"EventName\":\"%s\", "
                            "\"ProcessName\":\"%s\", "
                            "\"ProcessID\":%d, "
                            "\"ThreadID\":%d, "
                            "\"ProcessType\":\"%s\", "
                            "\"Arguments\":{"
                            "\"Inode\":%lld, "
                            "\"FileUser\":%d, "
                            "\"FileMode\":%d, "
                            "\"ReadBytes\":%lld, "
                            "\"FileName\":\"%s\","
                            "} "
                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->event.filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"Inode\":%lld, "
                                         "\"FileUser\":%d, "
                                         "\"FileMode\":%d, "
                                         "\"ReadBytes\":%lld, "
                                         "\"FileName\":\"%s\"}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->event.filename);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->readFileArguments.inode,
                           e->readFileArguments.fileuser,
                           e->readFileArguments.filemode,
                           e->readFileArguments.read_bytes,
                           e->event.filename);
                }
            }
            break;
        }
        case EVENT_FILE_WRITE_FILE: {
            event_type = (char *) "WRITE_FILE";
            struct WriteFileEvent *e = (struct WriteFileEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"Inode\":%lld, "
                                         "\"FileUser\":%d, "
                                         "\"FileMode\":%d, "
                                         "\"ReadBytes\":%lld, "
                                         "\"FileName\":\"%s\","
                                         "} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->writeFileArguments.inode,
                            e->writeFileArguments.fileuser,
                            e->writeFileArguments.filemode,
                            e->writeFileArguments.write_bytes,
                            e->event.filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"Inode\":%lld, "
                                         "\"FileUser\":%d, "
                                         "\"FileMode\":%d, "
                                         "\"ReadBytes\":%lld, "
                                         "\"FileName\":\"%s\"}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->writeFileArguments.inode,
                            e->writeFileArguments.fileuser,
                            e->writeFileArguments.filemode,
                            e->writeFileArguments.write_bytes,
                            e->event.filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->writeFileArguments.inode,
                            e->writeFileArguments.fileuser,
                            e->writeFileArguments.filemode,
                            e->writeFileArguments.write_bytes,
                            e->event.filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Inode\":%lld, "
                           "\"FileUser\":%d, "
                           "\"FileMode\":%d, "
                           "\"ReadBytes\":%lld, "
                           "\"FileName\":\"%s\","
                           "} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->writeFileArguments.inode,
                           e->writeFileArguments.fileuser,
                           e->writeFileArguments.filemode,
                           e->writeFileArguments.write_bytes,
                           e->event.filename);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"Inode\":%lld, "
                                         "\"FileUser\":%d, "
                                         "\"FileMode\":%d, "
                                         "\"ReadBytes\":%lld, "
                                         "\"FileName\":\"%s\"}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->writeFileArguments.inode,
                            e->writeFileArguments.fileuser,
                            e->writeFileArguments.filemode,
                            e->writeFileArguments.write_bytes,
                            e->event.filename);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->writeFileArguments.inode,
                           e->writeFileArguments.fileuser,
                           e->writeFileArguments.filemode,
                           e->writeFileArguments.write_bytes,
                           e->event.filename);
                }
            }
            break;
        }
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

            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->connectArguments.fd,
                            e->connectArguments.addrlen,
                            e->connectArguments.sa_family,
                            port,
                            ip);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d %-39s\n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
        case EVENT_NETWORK_SOCKET: {
            event_type = (char *) "SOCKET";
            struct SocketEvent *e = (struct SocketEvent *) data;
            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"SocketFamily\":%d, "
                                            "\"SocketType\":%d,"
                                            "\"Protocol\":%d}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->socketArguments.family,
                            e->socketArguments.type,
                            e->socketArguments.protocol);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"SocketFamily\":%d, "
                                            "\"SocketType\":%d,"
                                            "\"Protocol\":%d}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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

            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7hu %-7hu %-15u %u.%u.%u.%u\n",
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
                if (my_args.if_output_as_json)
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

            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"len\":%d, "
                                            "\"flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"len\":%d, "
                                            "\"flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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

            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"len\":%d, "
                                            "\"flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"len\":%d, "
                                            "\"flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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

            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Msg_flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Msg_flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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

            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Msg_flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d %-5d %-5d %-5d %-39s\n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Msg_flags\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                                            "\"Port\":%d,"
                                            "\"Address\":%s} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
        case EVENT_PROCESS_FORK: {
            event_type = (char *) "FORK";
            struct ForkEvent *e = (struct ForkEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"ParentPID\":%d, "
                                            "\"ParentPName\":\"%s\","
                                            "\"ChildPID\":%d,"
                                            "\"ChildPName\":\"%s\"} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->forkArguments.parent_pid,
                            e->forkArguments.parent_comm,
                            e->forkArguments.child_pid,
                            e->forkArguments.child_comm);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-10s\n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"ParentPID\":%d, "
                                            "\"ParentPName\":\"%s\","
                                            "\"ChildPID\":%d,"
                                            "\"ChildPName\":\"%s\"} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->forkArguments.parent_pid,
                            e->forkArguments.parent_comm,
                            e->forkArguments.child_pid,
                            e->forkArguments.child_comm);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"OldPID\":%d, "
                                            "\"PID\":%d,"
                                            "\"Executable\":\"%s\"}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->execArguments.old_pid,
                            e->execArguments.pid,
                            e->event.filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s \n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"OldPID\":%d, "
                                            "\"PID\":%d,"
                                            "\"Executable\":\"%s\"}}"
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->execArguments.old_pid,
                            e->execArguments.pid,
                            e->event.filename);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"CloneFlags\":%ld, "
                                            "\"NewSP\":%ld,"
                                            "\"TLS\":%ld,"
                                            "\"ParentTidPtr\":%p,"
                                            "\"ChildTidPtr\":%p"
                           "}}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->cloneArguments.clone_flags,
                            e->cloneArguments.newsp,
                            e->cloneArguments.tls,
                            e->cloneArguments.parent_tidptr,
                            e->cloneArguments.child_tidptr
                    );
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-10p %-10p \n",
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
                if (my_args.if_output_as_json) {
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"CloneFlags\":%ld, "
                                            "\"NewSP\":%ld,"
                                            "\"TLS\":%ld,"
                                            "\"ParentTidPtr\":%p,"
                                            "\"ChildTidPtr\":%p"
                           "}}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->cloneArguments.clone_flags,
                            e->cloneArguments.newsp,
                            e->cloneArguments.tls,
                            e->cloneArguments.parent_tidptr,
                            e->cloneArguments.child_tidptr
                    );
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Exit_code\":%d, "
                                            "\"PID\":%d, "
                                            "\"ExitPName\":%s,"
                                            "\"Priority\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->exitArguments.exit_code,
                            e->exitArguments.pid,
                            e->exitArguments.comm,
                            e->exitArguments.prio);
                } 
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-5d %-7d %-20s %-7d \n",
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
                if (my_args.if_output_as_json) {
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Exit_code\":%d, "
                                            "\"PID\":%d, "
                                            "\"ExitPName\":%s,"
                                            "\"Priority\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
        /// Kellect v1.1
        case EVENT_FILE_DUP:{
            event_type = (char *) "DUP";
            struct DupFileEvent *e = (struct DupFileEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                    * output the record as json
                    */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fildes\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->dupFileArguments.dup_fildes);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fildes\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->dupFileArguments.dup_fildes);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->dupFileArguments.dup_fildes);
                }
            }
                /**
                    * output the record as json
                    */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fildes\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->dupFileArguments.dup_fildes);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fildes\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->dupFileArguments.dup_fildes);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->dupFileArguments.dup_fildes);
                }
            }
            break;
        }
        case EVENT_FILE_DUP_2:{
            event_type = (char *) "DUP2";
            struct Dup2FileEvent *e = (struct Dup2FileEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                    * output the record as json
                    */
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"oldfd\":%d, "
                                         "\"newfd\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->dup2FileArguments.dup2_oldfd,
                            e->dup2FileArguments.dup2_newfd);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldfd\":%d, "
                                         "\"newfd\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->dup2FileArguments.dup2_oldfd,
                            e->dup2FileArguments.dup2_newfd);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->dup2FileArguments.dup2_oldfd,
                            e->dup2FileArguments.dup2_newfd);
                }
            }
                /**
                    * output the record as json
                    */
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"oldfd\":%d, "
                           "\"newfd\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->dup2FileArguments.dup2_oldfd,
                           e->dup2FileArguments.dup2_newfd);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldfd\":%d, "
                                         "\"newfd\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->dup2FileArguments.dup2_oldfd,
                            e->dup2FileArguments.dup2_newfd);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->dup2FileArguments.dup2_oldfd,
                           e->dup2FileArguments.dup2_newfd);
                }
            }
            break;
        }
        case EVENT_FILE_CLOSE:{
            event_type = (char *) "CLOSE"; //
            struct CloseFileEvent *e = (struct CloseFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->closeFileArguments.close_fd);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->closeFileArguments.close_fd);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->closeFileArguments.close_fd);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->closeFileArguments.close_fd);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->closeFileArguments.close_fd);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->closeFileArguments.close_fd);
                }
            }
            break;
        }
        case EVENT_FILE_FTRUNCATE:{
            event_type = (char *) "FTRUNCATE"; //
            struct FtruncateFileEvent *e = (struct FtruncateFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d, "
                                         "\"length\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->ftruncateFileArguments.ftruncate_fd,
                            e->ftruncateFileArguments.ftruncate_length);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d, "
                                         "\"length\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->ftruncateFileArguments.ftruncate_fd,
                            e->ftruncateFileArguments.ftruncate_length);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->ftruncateFileArguments.ftruncate_fd,
                            e->ftruncateFileArguments.ftruncate_length);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"length\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->ftruncateFileArguments.ftruncate_fd,
                           e->ftruncateFileArguments.ftruncate_length);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d, "
                                         "\"length\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->ftruncateFileArguments.ftruncate_fd,
                            e->ftruncateFileArguments.ftruncate_length);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->ftruncateFileArguments.ftruncate_fd,
                           e->ftruncateFileArguments.ftruncate_length);
                }
            }
            break;
        }
        case EVENT_FILE_CHMOD:{
            event_type = (char *) "CHMOD"; //
            struct ChmodFileEvent *e = (struct ChmodFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"pathname\":\"%s\", "
                                         "\"mode\":%o} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->chmodFileArguments.chmod_pathname,
                            e->chmodFileArguments.mode);// Octal is used here
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"pathname\":\"%s\", "
                                         "\"mode\":%o} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->chmodFileArguments.chmod_pathname,
                            e->chmodFileArguments.mode);// Octal is used here
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7s %-7o\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->chmodFileArguments.chmod_pathname,
                            e->chmodFileArguments.mode);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"pathname\":\"%s\", "
                           "\"mode\":%o} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->chmodFileArguments.chmod_pathname,
                           e->chmodFileArguments.mode);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"pathname\":\"%s\", "
                                         "\"mode\":%o} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->chmodFileArguments.chmod_pathname,
                            e->chmodFileArguments.mode);// Octal is used here
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7s %-7o\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->chmodFileArguments.chmod_pathname,
                           e->chmodFileArguments.mode);
                }
            }
            break;
        }
        case EVENT_FILE_FCHDIR:{
            event_type = (char *) "FCHMOD"; //
            struct FchdirFileEvent *e = (struct FchdirFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->fchdirFileArguments.fchdir_fd);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                        "\"fd\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->fchdirFileArguments.fchdir_fd);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->fchdirFileArguments.fchdir_fd);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->fchdirFileArguments.fchdir_fd);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                        "\"fd\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->fchdirFileArguments.fchdir_fd);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->fchdirFileArguments.fchdir_fd);
                }
            }
            break;
        }
        case EVENT_FILE_LINK:{
            event_type = (char *) "LINK"; //
            struct LinkFileEvent *e = (struct LinkFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"oldpath\":\"%s\", "
                                         "\"newpath\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->linkFileArguments.link_oldpath,
                            e->linkFileArguments.link_newpath);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldpath\":\"%s\", "
                                         "\"newpath\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->linkFileArguments.link_oldpath,
                            e->linkFileArguments.link_newpath);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7s %-7s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->linkFileArguments.link_oldpath,
                            e->linkFileArguments.link_newpath);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"oldpath\":\"%s\", "
                           "\"newpath\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->linkFileArguments.link_oldpath,
                           e->linkFileArguments.link_newpath);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldpath\":\"%s\", "
                                         "\"newpath\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->linkFileArguments.link_oldpath,
                            e->linkFileArguments.link_newpath);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7s %-7s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->linkFileArguments.link_oldpath,
                           e->linkFileArguments.link_newpath);
                }
            }
            break;
        }
        case EVENT_FILE_LINKAT:{
            event_type = (char *) "LINKAT"; //
            struct LinkatFileEvent *e = (struct LinkatFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"olddfd\":%d, "
                                         "\"oldname\":\"%s\","
                                         "\"newdfd\":%d, "
                                         "\"newname\":\"%s\","
                                         "\"flags\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->linkatFileArguments.linkat_olddfd,
                            e->linkatFileArguments.linkat_oldname,
                            e->linkatFileArguments.linkat_newdfd,
                            e->linkatFileArguments.linkat_newname,
                            e->linkatFileArguments.linkat_flags);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"olddfd\":%d, "
                                         "\"oldname\":\"%s\","
                                         "\"newdfd\":%d, "
                                         "\"newname\":\"%s\","
                                         "\"flags\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->linkatFileArguments.linkat_olddfd,
                            e->linkatFileArguments.linkat_oldname,
                            e->linkatFileArguments.linkat_newdfd,
                            e->linkatFileArguments.linkat_newname,
                            e->linkatFileArguments.linkat_flags);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7s %-7d %-7s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->linkatFileArguments.linkat_olddfd,
                            e->linkatFileArguments.linkat_oldname,
                            e->linkatFileArguments.linkat_newdfd,
                            e->linkatFileArguments.linkat_newname,
                            e->linkatFileArguments.linkat_flags);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"olddfd\":%d, "
                           "\"oldname\":\"%s\","
                           "\"newdfd\":%d, "
                           "\"newname\":\"%s\","
                           "\"flags\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->linkatFileArguments.linkat_olddfd,
                           e->linkatFileArguments.linkat_oldname,
                           e->linkatFileArguments.linkat_newdfd,
                           e->linkatFileArguments.linkat_newname,
                           e->linkatFileArguments.linkat_flags);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"olddfd\":%d, "
                                         "\"oldname\":\"%s\","
                                         "\"newdfd\":%d, "
                                         "\"newname\":\"%s\","
                                         "\"flags\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->linkatFileArguments.linkat_olddfd,
                            e->linkatFileArguments.linkat_oldname,
                            e->linkatFileArguments.linkat_newdfd,
                            e->linkatFileArguments.linkat_newname,
                            e->linkatFileArguments.linkat_flags);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7s %-7d %-7s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->linkatFileArguments.linkat_olddfd,
                           e->linkatFileArguments.linkat_oldname,
                           e->linkatFileArguments.linkat_newdfd,
                           e->linkatFileArguments.linkat_newname,
                           e->linkatFileArguments.linkat_flags);
                }
            }
            break;
        }
        case EVENT_FILE_FCHMOD:{
            event_type = (char *) "FCHMOD"; //
            struct FchmodFileEvent *e = (struct FchmodFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d, "
                                         "\"mode\":%o} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->fchmodFileArguments.fchmod_fd,
                            e->fchmodFileArguments.fchmod_mode);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d, "
                                         "\"mode\":%o} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->fchmodFileArguments.fchmod_fd,
                            e->fchmodFileArguments.fchmod_mode);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7o\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->fchmodFileArguments.fchmod_fd,
                            e->fchmodFileArguments.fchmod_mode);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"mode\":%o} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->fchmodFileArguments.fchmod_fd,
                           e->fchmodFileArguments.fchmod_mode);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d, "
                                         "\"mode\":%o} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->fchmodFileArguments.fchmod_fd,
                            e->fchmodFileArguments.fchmod_mode);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7o\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->fchmodFileArguments.fchmod_fd,
                           e->fchmodFileArguments.fchmod_mode);
                }
            }
            break;
        }
        case EVENT_FILE_MKDIRAT:{
            event_type = (char *) "MKDIRAT"; //
            struct MkdiratFileEvent *e = (struct MkdiratFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"dfd\":%d, "
                                         "\"pathname\":\"%s\", "
                                         "\"mode\":%o} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->mkdiratFileArguments.mkdirat_dfd,
                            e->mkdiratFileArguments.mkdirat_name,
                            e->mkdiratFileArguments.mkdirat_mode);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"dfd\":%d, "
                                         "\"pathname\":\"%s\", "
                                         "\"mode\":%o} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->mkdiratFileArguments.mkdirat_dfd,
                            e->mkdiratFileArguments.mkdirat_name,
                            e->mkdiratFileArguments.mkdirat_mode);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7o\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->mkdiratFileArguments.mkdirat_dfd,
                            e->mkdiratFileArguments.mkdirat_name,
                            e->mkdiratFileArguments.mkdirat_mode);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"dfd\":%d, "
                           "\"pathname\":\"%s\", "
                           "\"mode\":%o} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->mkdiratFileArguments.mkdirat_dfd,
                           e->mkdiratFileArguments.mkdirat_name,
                           e->mkdiratFileArguments.mkdirat_mode);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"dfd\":%d, "
                                         "\"pathname\":\"%s\", "
                                         "\"mode\":%o} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->mkdiratFileArguments.mkdirat_dfd,
                            e->mkdiratFileArguments.mkdirat_name,
                            e->mkdiratFileArguments.mkdirat_mode);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7o\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->mkdiratFileArguments.mkdirat_dfd,
                           e->mkdiratFileArguments.mkdirat_name,
                           e->mkdiratFileArguments.mkdirat_mode);
                }
            }
            break;
        }
        case EVENT_FILE_RENAME:{
            event_type = (char *) "RENAME"; //
            struct RenameFileEvent *e = (struct RenameFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"newname\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameFileArguments.rename_oldname,
                            e->renameFileArguments.rename_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"newname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->renameFileArguments.rename_oldname,
                            e->renameFileArguments.rename_newname);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameFileArguments.rename_oldname,
                            e->renameFileArguments.rename_newname);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"oldname\":\"%s\", "
                           "\"newname\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->renameFileArguments.rename_oldname,
                           e->renameFileArguments.rename_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"newname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->renameFileArguments.rename_oldname,
                            e->renameFileArguments.rename_newname);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-10s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->renameFileArguments.rename_oldname,
                           e->renameFileArguments.rename_newname);
                }
            }
            break;
        }
        case EVENT_FILE_RENAMEAT:{
            event_type = (char *) "RENAMEAT"; //
            struct RenameatFileEvent *e = (struct RenameatFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"oldfd\":%d, "
                                         "\"oldname\":\"%s\", "
                                         "\"newfd\":%d, "
                                         "\"newname\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameatFileArguments.renameat_oldfd,
                            e->renameatFileArguments.renameat_oldname,
                            e->renameatFileArguments.renameat_newfd,
                            e->renameatFileArguments.renameat_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldfd\":%d, "
                                         "\"oldname\":\"%s\", "
                                         "\"newfd\":%d, "
                                         "\"newname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->renameatFileArguments.renameat_oldfd,
                            e->renameatFileArguments.renameat_oldname,
                            e->renameatFileArguments.renameat_newfd,
                            e->renameatFileArguments.renameat_newname);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameatFileArguments.renameat_oldfd,
                            e->renameatFileArguments.renameat_oldname,
                            e->renameatFileArguments.renameat_newfd,
                            e->renameatFileArguments.renameat_newname);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"oldfd\":%d, "
                           "\"oldname\":\"%s\", "
                           "\"newfd\":%d, "
                           "\"newname\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->renameatFileArguments.renameat_oldfd,
                           e->renameatFileArguments.renameat_oldname,
                           e->renameatFileArguments.renameat_newfd,
                           e->renameatFileArguments.renameat_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldfd\":%d, "
                                         "\"oldname\":\"%s\", "
                                         "\"newfd\":%d, "
                                         "\"newname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->renameatFileArguments.renameat_oldfd,
                            e->renameatFileArguments.renameat_oldname,
                            e->renameatFileArguments.renameat_newfd,
                            e->renameatFileArguments.renameat_newname);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-10s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->renameatFileArguments.renameat_oldfd,
                           e->renameatFileArguments.renameat_oldname,
                           e->renameatFileArguments.renameat_newfd,
                           e->renameatFileArguments.renameat_newname);
                }
            }
            break;
        }
        case EVENT_FILE_SYMLINK:{
            event_type = (char *) "SYMLINK"; //
            struct SymlinkFileEvent *e = (struct SymlinkFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"pnewname\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->symlinkFileArguments.symlink_oldname,
                            e->symlinkFileArguments.symlink_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"pnewname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->symlinkFileArguments.symlink_oldname,
                            e->symlinkFileArguments.symlink_newname);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->symlinkFileArguments.symlink_oldname,
                            e->symlinkFileArguments.symlink_newname);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"oldname\":\"%s\", "
                           "\"pnewname\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->symlinkFileArguments.symlink_oldname,
                           e->symlinkFileArguments.symlink_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"pnewname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->symlinkFileArguments.symlink_oldname,
                            e->symlinkFileArguments.symlink_newname);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-10s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->symlinkFileArguments.symlink_oldname,
                           e->symlinkFileArguments.symlink_newname);
                }
            }
            break;
        }
        case EVENT_FILE_SYMLINKAT:{
            event_type = (char *) "SYMLINKAT"; //
            struct SymlinkatFileEvent *e = (struct SymlinkatFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"fd\":%d, "
                                         "\"pnewname\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->symlinkatFileArguments.symlinkat_oldname,
                            e->symlinkatFileArguments.symlinkat_fd,
                            e->symlinkatFileArguments.symlinkat_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"fd\":%d, "
                                         "\"pnewname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->symlinkatFileArguments.symlinkat_oldname,
                            e->symlinkatFileArguments.symlinkat_fd,
                            e->symlinkatFileArguments.symlinkat_newname);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-7d %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->symlinkatFileArguments.symlinkat_oldname,
                            e->symlinkatFileArguments.symlinkat_fd,
                            e->symlinkatFileArguments.symlinkat_newname);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"oldname\":\"%s\", "
                           "\"fd\":%d, "
                           "\"pnewname\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->symlinkatFileArguments.symlinkat_oldname,
                           e->symlinkatFileArguments.symlinkat_fd,
                           e->symlinkatFileArguments.symlinkat_newname);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"oldname\":\"%s\", "
                                         "\"fd\":%d, "
                                         "\"pnewname\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->symlinkatFileArguments.symlinkat_oldname,
                            e->symlinkatFileArguments.symlinkat_fd,
                            e->symlinkatFileArguments.symlinkat_newname);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-7d %-10s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->symlinkatFileArguments.symlinkat_oldname,
                           e->symlinkatFileArguments.symlinkat_fd,
                           e->symlinkatFileArguments.symlinkat_newname);
                }
            }
            break;
        }
        case EVENT_FILE_UNLINK:{
            event_type = (char *) "UNLINK"; //
            struct UnlinkFileEvent *e = (struct UnlinkFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"name\":\"%s\"} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->unlinkFileArguments.unlink_name);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"name\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->unlinkFileArguments.unlink_name);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->unlinkFileArguments.unlink_name);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"name\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->unlinkFileArguments.unlink_name);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"name\":\"%s\"} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->unlinkFileArguments.unlink_name);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-10s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->unlinkFileArguments.unlink_name);
                }
            }
            break;
        }
        case EVENT_FILE_TRUNCATE:{
            event_type = (char *) "TRUNCATE"; //
            struct TruncateFileEvent *e = (struct TruncateFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"path\":\"%s\", "
                                         "\"length\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->truncateFileArguments.truncate_path,
                            e->truncateFileArguments.length);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"path\":\"%s\", "
                                         "\"length\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->truncateFileArguments.truncate_path,
                            e->truncateFileArguments.length);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->truncateFileArguments.truncate_path,
                            e->truncateFileArguments.length);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"path\":\"%s\", "
                           "\"length\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->truncateFileArguments.truncate_path,
                           e->truncateFileArguments.length);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"path\":\"%s\", "
                                         "\"length\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->truncateFileArguments.truncate_path,
                            e->truncateFileArguments.length);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->truncateFileArguments.truncate_path,
                           e->truncateFileArguments.length);
                }
            }
            break;
        }
        case EVENT_FILE_PREAD64:{
            event_type = (char *) "PREAD64"; //
            struct Pread64FileEvent *e = (struct Pread64FileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         //"\"buf\":\"%s\","
                                         "\"size\":%d,"
                                         "\"pos\":%d}"
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pread64FileArguments.read_fd,
                            //e->pread64FileArguments.read_buff,
                            e->pread64FileArguments.read_size,
                            e->pread64FileArguments.read_pos);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"size\":%d,"
                                         "\"pos\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pread64FileArguments.read_fd,
                            e->pread64FileArguments.read_size,
                            e->pread64FileArguments.read_pos);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pread64FileArguments.read_fd,
                            //e->pread64FileArguments.read_buff,
                            e->pread64FileArguments.read_size,
                            e->pread64FileArguments.read_pos);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d,"
                           //"\"buf\":\"%s\","
                           "\"size\":%d,"
                           "\"pos\":%d}"
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->pread64FileArguments.read_fd,
                            //e->pread64FileArguments.read_buff,
                           e->pread64FileArguments.read_size,
                           e->pread64FileArguments.read_pos);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"size\":%d,"
                                         "\"pos\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pread64FileArguments.read_fd,
                            e->pread64FileArguments.read_size,
                            e->pread64FileArguments.read_pos);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->pread64FileArguments.read_fd,
                            //e->pread64FileArguments.read_buff,
                           e->pread64FileArguments.read_size,
                           e->pread64FileArguments.read_pos);
                }
            }
            break;
        }
        case EVENT_FILE_PREADV:{
            event_type = (char *) "PREADV"; //
            struct PreadvFileEvent *e = (struct PreadvFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"vlen\":%d,"
                                         "\"pos_l\":%d,"
                                         "\"pos_h\":%d}"
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->preadvFileArguments.read_fd,
                            e->preadvFileArguments.read_vlen,
                            e->preadvFileArguments.read_pos_l,
                            e->preadvFileArguments.read_pos_h);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"vlen\":%d,"
                                         "\"pos_l\":%d,"
                                         "\"pos_h\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->preadvFileArguments.read_fd,
                            e->preadvFileArguments.read_vlen,
                            e->preadvFileArguments.read_pos_l,
                            e->preadvFileArguments.read_pos_h);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->preadvFileArguments.read_fd,
                            e->preadvFileArguments.read_vlen,
                            e->preadvFileArguments.read_pos_l,
                            e->preadvFileArguments.read_pos_h);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d,"
                           "\"vlen\":%d,"
                           "\"pos_l\":%d,"
                           "\"pos_h\":%d}"
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->preadvFileArguments.read_fd,
                           e->preadvFileArguments.read_vlen,
                           e->preadvFileArguments.read_pos_l,
                           e->preadvFileArguments.read_pos_h);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"vlen\":%d,"
                                         "\"pos_l\":%d,"
                                         "\"pos_h\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->preadvFileArguments.read_fd,
                            e->preadvFileArguments.read_vlen,
                            e->preadvFileArguments.read_pos_l,
                            e->preadvFileArguments.read_pos_h);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->preadvFileArguments.read_fd,
                           e->preadvFileArguments.read_vlen,
                           e->preadvFileArguments.read_pos_l,
                           e->preadvFileArguments.read_pos_h);
                }
            }
            break;
        }
        case EVENT_FILE_PWRITE64:{
            event_type = (char *) "PWRITE64"; //
            struct Pwrite64FileEvent *e = (struct Pwrite64FileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"size\":%d,"
                                         "\"pos\":%d}"
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pwrite64FileArguments.write_fd,
                            e->pwrite64FileArguments.write_size,
                            e->pwrite64FileArguments.write_pos);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"size\":%d,"
                                         "\"pos\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pwrite64FileArguments.write_fd,
                            e->pwrite64FileArguments.write_size,
                            e->pwrite64FileArguments.write_pos);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pwrite64FileArguments.write_fd,
                            e->pwrite64FileArguments.write_size,
                            e->pwrite64FileArguments.write_pos);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d,"
                           "\"size\":%d,"
                           "\"pos\":%d}"
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->pwrite64FileArguments.write_fd,
                           e->pwrite64FileArguments.write_size,
                           e->pwrite64FileArguments.write_pos);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"size\":%d,"
                                         "\"pos\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pwrite64FileArguments.write_fd,
                            e->pwrite64FileArguments.write_size,
                            e->pwrite64FileArguments.write_pos);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->pwrite64FileArguments.write_fd,
                           e->pwrite64FileArguments.write_size,
                           e->pwrite64FileArguments.write_pos);
                }
            }
            break;
        }
        case EVENT_FILE_PWRITEV:{
            event_type = (char *) "PWRITEV"; //
            struct PwritevFileEvent *e = (struct PwritevFileEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"vlen\":%d,"
                                         "\"pos_l\":%d,"
                                         "\"pos_h\":%d}"
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pwritevFileArguments.write_fd,
                            e->pwritevFileArguments.write_vlen,
                            e->pwritevFileArguments.write_pos_l,
                            e->pwritevFileArguments.write_pos_h);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"vlen\":%d,"
                                         "\"pos_l\":%d,"
                                         "\"pos_h\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pwritevFileArguments.write_fd,
                            e->pwritevFileArguments.write_vlen,
                            e->pwritevFileArguments.write_pos_l,
                            e->pwritevFileArguments.write_pos_h);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pwritevFileArguments.write_fd,
                            e->pwritevFileArguments.write_vlen,
                            e->pwritevFileArguments.write_pos_l,
                            e->pwritevFileArguments.write_pos_h);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d,"
                           "\"vlen\":%d,"
                           "\"pos_l\":%d,"
                           "\"pos_h\":%d}"
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->pwritevFileArguments.write_fd,
                           e->pwritevFileArguments.write_vlen,
                           e->pwritevFileArguments.write_pos_l,
                           e->pwritevFileArguments.write_pos_h);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"fd\":%d,"
                                         "\"vlen\":%d,"
                                         "\"pos_l\":%d,"
                                         "\"pos_h\":%d}"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pwritevFileArguments.write_fd,
                            e->pwritevFileArguments.write_vlen,
                            e->pwritevFileArguments.write_pos_l,
                            e->pwritevFileArguments.write_pos_h);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->pwritevFileArguments.write_fd,
                           e->pwritevFileArguments.write_vlen,
                           e->pwritevFileArguments.write_pos_l,
                           e->pwritevFileArguments.write_pos_h);
                }
            }
            break;
        }
        case EVENT_SETGID:{
            event_type = (char *) "SETGID"; //
            struct SetgidEvent *e = (struct SetgidEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"gid\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setgidArguments.gid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                           "\"gid\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setgidArguments.gid);
                }  
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setgidArguments.gid);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"gid\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setgidArguments.gid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                           "\"gid\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setgidArguments.gid);
                } 
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setgidArguments.gid);
                }
            }
            break;
        }
        case EVENT_SETUID:{
            event_type = (char *) "SETUID"; //
            struct SetuidEvent *e = (struct SetuidEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"uid\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setuidArguments.uid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"uid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setuidArguments.uid);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setuidArguments.uid);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"uid\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setuidArguments.uid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"uid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setuidArguments.uid);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setuidArguments.uid);
                }
            }
            break;
        }
        case EVENT_SETREGID:{
            event_type = (char *) "SETREGID"; //
            struct SetregidEvent *e = (struct SetregidEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"rgid\":%d "
                                         "\"egid\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setregidArguments.setregid_rgid,
                            e->setregidArguments.setregid_egid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"rgid\":%d "
                                         "\"egid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setregidArguments.setregid_rgid,
                            e->setregidArguments.setregid_egid);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setregidArguments.setregid_rgid,
                            e->setregidArguments.setregid_egid);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"rgid\":%d "
                           "\"egid\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setregidArguments.setregid_rgid,
                           e->setregidArguments.setregid_egid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"rgid\":%d "
                                         "\"egid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setregidArguments.setregid_rgid,
                            e->setregidArguments.setregid_egid);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setregidArguments.setregid_rgid,
                           e->setregidArguments.setregid_egid);
                }
            }
            break;
        }
        case EVENT_SETRESGID:{
            event_type = (char *) "SETRESGID"; //
            struct SetresgidEvent *e = (struct SetresgidEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"rgid\":%d "
                                         "\"egid\":%d "
                                         "\"sgid\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setresgidArguments.setresgid_rgid,
                            e->setresgidArguments.setresgid_egid,
                            e->setresgidArguments.setresgid_sgid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"rgid\":%d "
                                         "\"egid\":%d "
                                         "\"sgid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setresgidArguments.setresgid_rgid,
                            e->setresgidArguments.setresgid_egid,
                            e->setresgidArguments.setresgid_sgid);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setresgidArguments.setresgid_rgid,
                            e->setresgidArguments.setresgid_egid,
                            e->setresgidArguments.setresgid_sgid);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"rgid\":%d "
                           "\"egid\":%d "
                           "\"sgid\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setresgidArguments.setresgid_rgid,
                           e->setresgidArguments.setresgid_egid,
                           e->setresgidArguments.setresgid_sgid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"rgid\":%d "
                                         "\"egid\":%d "
                                         "\"sgid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setresgidArguments.setresgid_rgid,
                            e->setresgidArguments.setresgid_egid,
                            e->setresgidArguments.setresgid_sgid);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setresgidArguments.setresgid_rgid,
                           e->setresgidArguments.setresgid_egid,
                           e->setresgidArguments.setresgid_sgid);
                }
            }
            break;
        }
        case EVENT_SETRESUID:{
            event_type = (char *) "SETRESUID"; //
            struct SetresuidEvent *e = (struct SetresuidEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"ruid\":%d "
                                         "\"euid\":%d "
                                         "\"suid\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setresuidArguments.setresuid_ruid,
                            e->setresuidArguments.setresuid_euid,
                            e->setresuidArguments.setresuid_suid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ruid\":%d "
                                         "\"euid\":%d "
                                         "\"suid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setresuidArguments.setresuid_ruid,
                            e->setresuidArguments.setresuid_euid,
                            e->setresuidArguments.setresuid_suid);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setresuidArguments.setresuid_ruid,
                            e->setresuidArguments.setresuid_euid,
                            e->setresuidArguments.setresuid_suid);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"ruid\":%d "
                           "\"euid\":%d "
                           "\"suid\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setresuidArguments.setresuid_ruid,
                           e->setresuidArguments.setresuid_euid,
                           e->setresuidArguments.setresuid_suid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ruid\":%d "
                                         "\"euid\":%d "
                                         "\"suid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setresuidArguments.setresuid_ruid,
                            e->setresuidArguments.setresuid_euid,
                            e->setresuidArguments.setresuid_suid);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setresuidArguments.setresuid_ruid,
                           e->setresuidArguments.setresuid_euid,
                           e->setresuidArguments.setresuid_suid);
                }
            }
            break;
        }
        case EVENT_SETREUID:{
            event_type = (char *) "SETREUID"; //
            struct SetreuidEvent *e = (struct SetreuidEvent *) data; //
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    //output the record as json
                    fprintf(output_all, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"ruid\":%d "
                                         "\"euid\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setreuidArguments.setreuid_ruid,
                            e->setreuidArguments.setreuid_euid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ruid\":%d "
                                         "\"euid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setreuidArguments.setreuid_ruid,
                            e->setreuidArguments.setreuid_euid);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setreuidArguments.setreuid_ruid,
                            e->setreuidArguments.setreuid_euid);
                }
            }
                //output to console/shell
            else {
                if (my_args.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"ruid\":%d "
                           "\"euid\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setreuidArguments.setreuid_ruid,
                           e->setreuidArguments.setreuid_euid);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                         "\"ruid\":%d "
                                         "\"euid\":%d} "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->setreuidArguments.setreuid_ruid,
                            e->setreuidArguments.setreuid_euid);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setreuidArguments.setreuid_ruid,
                           e->setreuidArguments.setreuid_euid);
                }
            }
            break;
        }
        case EVENT_PROCESS_PIPE: {
            event_type = (char *) "PIPE";
            struct PipeEvent *e = (struct PipeEvent *) data;
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pipeArguments.f1,
                            e->pipeArguments.f2);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d \n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pipeArguments.f1,
                            e->pipeArguments.f2);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                           "\"Flags\":%d, "
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pipe2Arguments.flags,e->pipe2Arguments.f1,
                            e->pipe2Arguments.f2);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                           "\"Flags\":%d, "
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->pipe2Arguments.flags,e->pipe2Arguments.f1,
                            e->pipe2Arguments.f2);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->killArguments.pid,
                            e->killArguments.sig);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->killArguments.pid,
                            e->killArguments.sig);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"size\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->clone3Arguments.size
                            );
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s  %-7d   \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->clone3Arguments.size
                            );
                }
            }
            /**
             * output to console/shell
             */
            else {
                if (my_args.if_output_as_json) {
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"size\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Filename\":\"%s\","
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->execveArguments.filename);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s  \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execveArguments.filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Filename\":\"%s\","
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->execveArguments.filename);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"FD\":%d, "
                                            "\"Filename\":\"%s\","
                                            "\"flags\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d\n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"FD\":%d, "
                                            "\"Filename\":\"%s\","
                                            "\"flags\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Code\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->exitgroupArguments.exit_code);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->exitgroupArguments.exit_code);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Code\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->exitgroupArguments.exit_code);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Request\":%ld, "
                                            "\"Pid\":%ld, "
                                            "\"Addr\":%ld, "
                                            "\"Data\":%ld, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->ptraceArguments.request,
                            e->ptraceArguments.pid,
                            e->ptraceArguments.addr,
                            e->ptraceArguments.data);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-7ld \n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Request\":%ld, "
                                            "\"Pid\":%ld, "
                                            "\"Addr\":%ld, "
                                            "\"Data\":%ld, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->ptraceArguments.request,
                            e->ptraceArguments.pid,
                            e->ptraceArguments.addr,
                            e->ptraceArguments.data);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                             "\"tgid\":%d, "
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->tgkillArguments.tgid,
                            e->tgkillArguments.pid,
                            e->tgkillArguments.sig);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                             "\"tgid\":%d, "
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->tgkillArguments.tgid,
                            e->tgkillArguments.pid,
                            e->tgkillArguments.sig);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->tkillArguments.pid,
                            e->tkillArguments.sig);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d \n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf("{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->tkillArguments.pid,
                            e->tkillArguments.sig);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type);
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Addr\":%ld, "
                                            "\"Len\":%ld, "
                                            "\"Prot\":%ld, "
                                            "\"Flags\":%ld, "
                                            "\"Fd\":%ld, "
                                            "\"Off\":%ld, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->mmapArguments.addr,
                            e->mmapArguments.len,
                            e->mmapArguments.prot,
                            e->mmapArguments.flags,
                            e->mmapArguments.fd,
                            e->mmapArguments.off);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7ld %-7ld %-7ld %-7ld %-7ld \n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Addr\":%ld, "
                                            "\"Len\":%ld, "
                                            "\"Prot\":%ld, "
                                            "\"Flags\":%ld, "
                                            "\"Fd\":%ld, "
                                            "\"Off\":%ld, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->mmapArguments.addr,
                            e->mmapArguments.len,
                            e->mmapArguments.prot,
                            e->mmapArguments.flags,
                            e->mmapArguments.fd,
                            e->mmapArguments.off);
                }
                else {
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
            if (my_args.if_output_to_file) {
                if (my_args.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Addr\":%ld, "
                                            "\"Len\":%zu, "
                                            "\"Prot\":%ld, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->mprotectArguments.start,
                            e->mprotectArguments.len,
                            e->mprotectArguments.prot);
                }
                else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7ld %-7zu %-7ld \n",
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
                if (my_args.if_output_as_json) {
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
                } 
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"Addr\":%ld, "
                                            "\"Len\":%zu, "
                                            "\"Prot\":%ld, "
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->mprotectArguments.start,
                            e->mprotectArguments.len,
                            e->mprotectArguments.prot);
                }
                else {
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
        case EVENT_NETWORK_ACCEPT: {
            event_type = (char *) "ACCEPT";
            struct AcceptEvent *e = (struct AcceptEvent *) data;
            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                                        "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->acceptArguments.fd,
                            e->acceptArguments.upper_addrlen,
                            e->acceptArguments.sa_family);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                        "\"fd\":%d, "
                                        "\"Addrlen\":%d,"
                                        "\"SaFamily\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->acceptArguments.fd,
                            e->acceptArguments.upper_addrlen,
                            e->acceptArguments.sa_family);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->acceptArguments.fd,
                            e->acceptArguments.upper_addrlen,
                            e->acceptArguments.sa_family);
                }
            }
                /**
                 * output to console/shell
                 */
            else
            {
                if (my_args.if_output_as_json)
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
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->acceptArguments.fd,
                           e->acceptArguments.upper_addrlen,
                           e->acceptArguments.sa_family);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                        "\"fd\":%d, "
                                        "\"Addrlen\":%d,"
                                        "\"SaFamily\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->acceptArguments.fd,
                            e->acceptArguments.upper_addrlen,
                            e->acceptArguments.sa_family);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->acceptArguments.fd,
                           e->acceptArguments.upper_addrlen,
                           e->acceptArguments.sa_family);
                }
            }
            break;
        }
        case EVENT_NETWORK_ACCEPT4: {
            event_type = (char *) "ACCEPT4";
            struct Accept4Event *e = (struct Accept4Event *) data;
            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                                        "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->accept4Arguments.fd,
                            e->accept4Arguments.upper_addrlen,
                            e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                        "\"fd\":%d, "
                                        "\"Addrlen\":%d,"
                                        "\"SaFamily\":%d,"
                                        "\"Flags\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->accept4Arguments.fd,
                            e->accept4Arguments.upper_addrlen,
                            e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->accept4Arguments.fd,
                            e->accept4Arguments.upper_addrlen,
                            e->accept4Arguments.sa_family,
                             e->accept4Arguments.flags);
                }
            }
                /**
                 * output to console/shell
                 */
            else
            {
                if (my_args.if_output_as_json)
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
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->accept4Arguments.fd,
                           e->accept4Arguments.upper_addrlen,
                           e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                        "\"fd\":%d, "
                                        "\"Addrlen\":%d,"
                                        "\"SaFamily\":%d,"
                                        "\"Flags\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->accept4Arguments.fd,
                            e->accept4Arguments.upper_addrlen,
                            e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-5d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->accept4Arguments.fd,
                           e->accept4Arguments.upper_addrlen,
                           e->accept4Arguments.sa_family,
                            e->accept4Arguments.flags);
                }
            }
            break;
        }
        case EVENT_NETWORK_BIND: {
            event_type = (char *) "BIND";
            struct BindEvent *e = (struct BindEvent *) data;
            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->bindArguments.fd,
                            e->bindArguments.addrlen,
                            e->bindArguments.sa_family);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->bindArguments.fd,
                            e->bindArguments.addrlen,
                            e->bindArguments.sa_family);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->bindArguments.fd,
                            e->bindArguments.addrlen,
                            e->bindArguments.sa_family);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args.if_output_as_json)
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
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->bindArguments.fd,
                           e->bindArguments.addrlen,
                           e->bindArguments.sa_family);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addrlen\":%d,"
                                            "\"SaFamily\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->bindArguments.fd,
                            e->bindArguments.addrlen,
                            e->bindArguments.sa_family);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->bindArguments.fd,
                           e->bindArguments.addrlen,
                           e->bindArguments.sa_family);
                }
            }
            break;
        }
         case EVENT_NETWORK_GETPEERNAME: {
            event_type = (char *) "GETPEERNAME";
            struct GetPeerNameEvent *e = (struct GetPeerNameEvent *) data;
            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->getpeernameArguments.fd,
                            e->getpeernameArguments.addr_len,
                            e->getpeernameArguments.sa_family);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addr_len\":%d,"
                                            "\"SaFamily\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->getpeernameArguments.fd,
                            e->getpeernameArguments.addr_len,
                            e->getpeernameArguments.sa_family);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->getpeernameArguments.fd,
                            e->getpeernameArguments.addr_len,
                            e->getpeernameArguments.sa_family);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args.if_output_as_json)
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
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->getpeernameArguments.fd,
                           e->getpeernameArguments.addr_len,
                           e->getpeernameArguments.sa_family);
                }
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Addr_len\":%d,"
                                            "\"SaFamily\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->getpeernameArguments.fd,
                            e->getpeernameArguments.addr_len,
                            e->getpeernameArguments.sa_family);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->getpeernameArguments.fd,
                           e->getpeernameArguments.addr_len,
                           e->getpeernameArguments.sa_family);
                }
            }
            break;
        }
        case EVENT_NETWORK_RECVMMSG: {
            event_type = (char *) "DS_RECVMMSG";
            struct RecvMmsgEvent *e = (struct RecvMmsgEvent *) data;
            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->recvmmsgArguments.fd,
                            e->recvmmsgArguments.flags,
                            e->recvmmsgArguments.vlen);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d  \n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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
            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->sendmmsgArguments.fd,
                            e->sendmmsgArguments.flags,
                            e->sendmmsgArguments.vlen);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-5d %-5d  \n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"fd\":%d, "
                                            "\"Flags\":%d, "
                                            "\"Addrlen\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
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

            if (my_args.if_output_to_file)
            {
                if (my_args.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_all, "{"
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_all, "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"family\":%d, "
                                            "\"type\":%d,"
                                            "\"protocol\":%d,"
                                             "\"Sv1\":%d,"
                                              "\"Sv2\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->socketpairArguments.family,
                            e->socketpairArguments.type,
                            e->socketpairArguments.protocol,
                            e->socketpairArguments.sv1,
                            e->socketpairArguments.sv2);
                }
                else
                {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-9d %-9d %-9d\n",
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
                if (my_args.if_output_as_json)
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
                else if (my_args.if_output_as_origin) {
                    //output the record as origin
                    printf( "{"
                    "\"Subject\":{"
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, " 
                           "\"ProcessType\":\"%s\"}"
                           "\"EVENT\":{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\"}"
                           "\"Object\":{"
                           "\"Arguments\":{"
                                            "\"family\":%d, "
                                            "\"type\":%d,"
                                            "\"protocol\":%d,"
                                             "\"Sv1\":%d,"
                                              "\"Sv2\":%d,"
                           "}}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                            e->socketpairArguments.family,
                            e->socketpairArguments.type,
                            e->socketpairArguments.protocol,
                            e->socketpairArguments.sv1,
                            e->socketpairArguments.sv2);
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


int test_all(Args args)
{
    my_args = args;

    if(my_args.if_output_to_file){
        output_all = fopen(my_args.output_file.c_str(),"w");
        if(output_all == NULL){
            fprintf(stderr, "please enter a valid file name/path\n");
            return 1;
        }
    }

    struct ring_buffer *rb = NULL;
    struct all_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = all_bpf__open();
    if(!skel){
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = all_bpf__load(skel);
    if(err){
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = all_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if(!rb){
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args.if_output_as_json&&!my_args.if_output_as_origin) {
        if (my_args.if_output_to_file) {
            fprintf(output_all, "%-20s %-10s %-32s %-7s %-7s %10s\n",
                    "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        } else {
            printf("%-20s %-10s %-32s %-7s %-7s %10s\n",
                   "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        }
    }

    while(!exiting) {
        err = ring_buffer__poll(rb, 10);
        if(err == -EINTR){
            err = 0;
            fclose(output_all);
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            fclose(output_all);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    all_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
