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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s %-7d %-7d\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s %-7d %-7d\n",
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s %-7d\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s %-7d\n",
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
                            e->renameArguments.rename_olddfd,
                            e->renameArguments.rename_oldname,
                            e->renameArguments.rename_newdfd,
                            e->renameArguments.rename_newname,
                            e->renameArguments.rename_flags);
                } else {
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s %-7d %-20s %-7d\n",
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
                           e->renameArguments.rename_olddfd,
                           e->renameArguments.rename_oldname,
                           e->renameArguments.rename_newdfd,
                           e->renameArguments.rename_newname,
                           e->renameArguments.rename_flags);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s %-7d %-20s %-7d\n",
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-7d %-20s\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-7d %-20s\n",
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
                                         "\"GetMode\":%o, "
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7o %-7d %-7d %-20s\n",
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
                           "\"GetMode\":%o, "
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7o %-7d %-7d %-20s\n",
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-20s\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-20s\n",
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7d %-20s\n",
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-20s\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-20s\n",
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7lld %-7d %-7d %-7lld %-20s\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7lld %-7d %-7d %-7lld %-20s\n",
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
                    fprintf(output_file, "%-20ld %-10s %-32s %-7d %-7d %-15s %-7lld %-7d %-7d %-7lld %-20s\n",
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
                    printf("%-20ld %-10s %-32s %-7d %-7d %-15s %-7lld %-7d %-7d %-7lld %-20s\n",
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

    /* Load & verify BPF programs */
    err = file_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = file_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_file_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args_file.if_output_as_json) {
        if (my_args_file.if_output_to_file) {
            fprintf(output_file, "%-20s %-10s %-32s %-7s %-7s %-15s %-s\n",
                    "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD", "--------------- PrivateProps ---------------");
        } else {
            printf("%-20s %-10s %-32s %-7s %-7s %-15s %-s\n",
                   "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD", "--------------- PrivateProps ---------------");
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
