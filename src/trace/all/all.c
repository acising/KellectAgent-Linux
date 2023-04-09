// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Created by zhuzhiling on 9/7/22.
//
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
        case EVENT_FILE_RENAME: {
            event_type = (char *) "RENAME";
            struct RenameEvent *e = (struct RenameEvent *) data;
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
                            e->renameArguments.rename_olddfd,
                            e->renameArguments.rename_oldname,
                            e->renameArguments.rename_newdfd,
                            e->renameArguments.rename_newname,
                            e->renameArguments.rename_flags);
                } else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-20s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameArguments.rename_olddfd,
                            e->renameArguments.rename_oldname,
                            e->renameArguments.rename_newdfd,
                            e->renameArguments.rename_newname,
                            e->renameArguments.rename_flags);
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
                           e->renameArguments.rename_olddfd,
                           e->renameArguments.rename_oldname,
                           e->renameArguments.rename_newdfd,
                           e->renameArguments.rename_newname,
                           e->renameArguments.rename_flags);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-20s %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->renameArguments.rename_olddfd,
                           e->renameArguments.rename_oldname,
                           e->renameArguments.rename_newdfd,
                           e->renameArguments.rename_newname,
                           e->renameArguments.rename_flags);
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
                } else {
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
                                         "\"FilePath\":\"%s\","
                                         "} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->readFileArguments.filepath);
                } else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->readFileArguments.filepath);
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
                            "\"FilePath\":\"%s\","
                            "} "
                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->readFileArguments.inode,
                            e->readFileArguments.fileuser,
                            e->readFileArguments.filemode,
                            e->readFileArguments.read_bytes,
                            e->readFileArguments.filepath);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->readFileArguments.inode,
                           e->readFileArguments.fileuser,
                           e->readFileArguments.filemode,
                           e->readFileArguments.read_bytes,
                           e->readFileArguments.filepath);
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
                                         "\"FilePath\":\"%s\","
                                         "} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->writeFileArguments.inode,
                            e->writeFileArguments.fileuser,
                            e->writeFileArguments.filemode,
                            e->writeFileArguments.write_bytes,
                            e->writeFileArguments.filepath);
                } else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->writeFileArguments.inode,
                            e->writeFileArguments.fileuser,
                            e->writeFileArguments.filemode,
                            e->writeFileArguments.write_bytes,
                            e->writeFileArguments.filepath);
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
                           "\"FilePath\":\"%s\","
                           "} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->writeFileArguments.inode,
                           e->writeFileArguments.fileuser,
                           e->writeFileArguments.filemode,
                           e->writeFileArguments.write_bytes,
                           e->writeFileArguments.filepath);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->writeFileArguments.inode,
                           e->writeFileArguments.fileuser,
                           e->writeFileArguments.filemode,
                           e->writeFileArguments.write_bytes,
                           e->writeFileArguments.filepath);
                }
            }
            break;
        }
        case EVENT_NETWORK_CONNECT: {
            event_type = (char *) "CONNECT";
            struct ConnectEvent *e = (struct ConnectEvent *) data;
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
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-5d %-25s\n",
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
        case EVENT_NETWORK_SEND: {
            event_type = (char *) "PKG_SEND";
            struct SendEvent *e = (struct SendEvent *) data;

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
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s\n",
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
                } else {
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
                } else {
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
                } else {
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
                                            "\"PID\":%d, "
                                            "\"ExitPName\":%s,"
                                            "\"Priority\":%d}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->exitArguments.pid,
                            e->exitArguments.comm,
                            e->exitArguments.prio);
                } else {
                    fprintf(output_all, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d \n",
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
                if (my_args.if_output_as_json) {
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
    if (!my_args.if_output_as_json) {
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
