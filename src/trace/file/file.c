// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "../../include/file.h"
#include "file.skel.h"
#include "../../include/arg_parser.h"
#include "../../include/basic.h"
#include <string.h>
#include <stdlib.h>

struct Args my_args_file;

FILE *output_file;

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (my_args_file.if_debug_mode) {
        return vfprintf(stderr, format, args);
    } else {
        return 0;
    }
}

static int handle_file_event(void *ctx, void *data, size_t data_sz) {
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
    if (strcmp("gnome-terminal-", e->comm) == 0 && my_args_file.if_output_to_file == false) {
        return 0;
    }

    char *event_type;

    switch (e->event_type) {
        /// Kellect v1.0
        case EVENT_FILE_OPEN: {
            event_type = (char *) "OPEN_FILE";
            struct OpenFileEvent *e = (struct OpenFileEvent *) data;
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
        case EVENT_FILE_RENAMEAT_2: {
            event_type = (char *) "RENAMEAT2";
            struct Renameat2Event *e = (struct Renameat2Event *) data;
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s %-7d %-20s %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s\n",
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
                if (my_args_file.if_output_as_json) {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-20s\n",
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
                if (my_args_file.if_output_as_json) {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->changeDirArguments.chdir_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args_file.if_output_as_json) {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,e->event.ppid, process_type,
                            e->makeDirArguments.mkdir_mode,
                            e->makeDirArguments.mkdir_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args_file.if_output_as_json) {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->removeDirArguments.rmdir_filename);
                }
            }
                /**
                 * output to console/shell
                 */
            else {
                if (my_args_file.if_output_as_json) {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                     * output the record as json
                     */
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7lld %-7d %-7d %-7lld %-20s\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
        /// Kellect v1.1
        case EVENT_FILE_DUP:{
            event_type = (char *) "DUP";
            struct DupFileEvent *e = (struct DupFileEvent *) data;
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                    * output the record as json
                    */
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->dupFileArguments.dup_fildes);
                }
            }
                /**
                    * output the record as json
                    */
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    /**
                    * output the record as json
                    */
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
                if (my_args_file.if_output_to_file) {
                    if (my_args_file.if_output_as_json) {
                        //output the record as json
                        fprintf(output_file, "{"
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
                    } else {
                        fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                                getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                                e->event.ppid, process_type,
                                e->closeFileArguments.close_fd);
                    }
                }
                    //output to console/shell
                else {
                    if (my_args_file.if_output_as_json) {
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
                    } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->ftruncateFileArguments.ftruncate_fd,
                            e->ftruncateFileArguments.ftruncate_length);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
                                        "\"Timestamp\":%ld,"
                                        "\"EventName\":\"%s\", "
                                        "\"ProcessName\":\"%s\", "
                                        "\"ProcessID\":%d, "
                                        "\"ThreadID\":%d, "
                                        "\"ProcessType\":\"%s\", "
                                        "\"Arguments\":{"
                                        "\"pathname\":\"%s\", "
                                        "\"mode\":%d} "
                                        "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->chmodFileArguments.chmod_pathname,
                            e->chmodFileArguments.mode);// Octal is used here
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->chmodFileArguments.chmod_pathname,
                            e->chmodFileArguments.mode);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"pathname\":\"%s\", "
                           "\"mode\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->chmodFileArguments.chmod_pathname,
                           e->chmodFileArguments.mode);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7s %-7d\n",
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->fchdirFileArguments.fchdir_fd);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7s %-7s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->linkFileArguments.link_oldpath,
                            e->linkFileArguments.link_newpath);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7s %-7d %-7s %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
                                        "\"Timestamp\":%ld,"
                                        "\"EventName\":\"%s\", "
                                        "\"ProcessName\":\"%s\", "
                                        "\"ProcessID\":%d, "
                                        "\"ThreadID\":%d, "
                                        "\"ProcessType\":\"%s\", "
                                        "\"Arguments\":{"
                                        "\"fd\":%d, "
                                        "\"mode\":%d} "
                                        "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->fchmodFileArguments.fchmod_fd,
                            e->fchmodFileArguments.fchmod_mode);
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->fchmodFileArguments.fchmod_fd,
                            e->fchmodFileArguments.fchmod_mode);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"fd\":%d, "
                           "\"mode\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->fchmodFileArguments.fchmod_fd,
                           e->fchmodFileArguments.fchmod_mode);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
                                        "\"Timestamp\":%ld,"
                                        "\"EventName\":\"%s\", "
                                        "\"ProcessName\":\"%s\", "
                                        "\"ProcessID\":%d, "
                                        "\"ThreadID\":%d, "
                                        "\"ProcessType\":\"%s\", "
                                        "\"Arguments\":{"
                                        "\"dfd\":%d, "
                                        "\"pathname\":\"%s\", "
                                        "\"mode\":%d} "
                                        "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->mkdiratFileArguments.mkdirat_dfd,
                            e->mkdiratFileArguments.mkdirat_name,
                            e->mkdiratFileArguments.mkdirat_mode);
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->mkdiratFileArguments.mkdirat_dfd,
                            e->mkdiratFileArguments.mkdirat_name,
                            e->mkdiratFileArguments.mkdirat_mode);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                           "\"mode\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->mkdiratFileArguments.mkdirat_dfd,
                           e->mkdiratFileArguments.mkdirat_name,
                           e->mkdiratFileArguments.mkdirat_mode);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d\n",
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->renameFileArguments.rename_oldname,
                            e->renameFileArguments.rename_newname);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-10s\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->symlinkFileArguments.symlink_oldname,
                            e->symlinkFileArguments.symlink_newname);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-7d %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->symlinkatFileArguments.symlinkat_oldname,
                            e->symlinkatFileArguments.symlinkat_fd,
                            e->symlinkatFileArguments.symlinkat_newname);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->unlinkFileArguments.unlink_name);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->truncateFileArguments.truncate_path,
                            e->truncateFileArguments.length);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->pwrite64FileArguments.write_fd,
                            e->pwrite64FileArguments.write_size,
                            e->pwrite64FileArguments.write_pos);
                }
            }
                //output to console/shell
            else {
                if (my_args_file.if_output_as_json) {
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
                } else {
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
            if (my_args_file.if_output_to_file) {
                if (my_args_file.if_output_as_json) {
                    //output the record as json
                    fprintf(output_file, "{"
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
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d %-7d\n",
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
                if (my_args_file.if_output_as_json) {
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
                } else {
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
    }
    return 0;
}

int test_file(Args args) {
    my_args_file = args;

    if (my_args_file.if_output_to_file) {
        output_file = fopen(my_args_file.output_file.c_str(), "w");
        if (output_file == NULL) {
            fprintf(stderr, "please enter a valid file name/path\n");
            return 1;
        }
    }

    struct ring_buffer *rb = NULL;
    struct file_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Load and verify BPF application */
    skel = file_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    printf("=========================Open=========================");

    /* Load & verify BPF programs */
    err = file_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    printf("=========================Load=========================");

    /* Attach tracepoints */
    err = file_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("=========================Attach=========================");

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_file_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("=========================Ring Buffer=========================");

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args_file.if_output_as_json) {
        if (my_args_file.if_output_to_file) {
            fprintf(output_file, "%-20s %-10s %-32s %-7s %-7s %10s\n",
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
            fclose(output_file);
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            fclose(output_file);
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    file_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
