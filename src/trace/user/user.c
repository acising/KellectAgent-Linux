// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "../../include/user.h"
#include "user.skel.h"
#include "../../include/arg_parser.h"
#include "../../include/basic.h"
#include <string.h>
#include <stdlib.h>
#include <ostream>
#include <iostream>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <execinfo.h>

struct Args my_args_user;
void *dladdr(void *addr, Dl_info *info);

FILE *output_user;

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (my_args_user.if_debug_mode) {
        return vfprintf(stderr, format, args);
    } else {
        return 0;
    }
}

static int handle_user_event(void *ctx, void *data, size_t data_sz) {
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
    if (strcmp("gnome-terminal-", e->comm) == 0 && my_args_user.if_output_to_file == false) {
        return 0;
    }
    char *event_type;
printf(" %d\n",
                   IPPROTO_ICMP);
    switch (e->event_type) {
        case EVENT_SETGID:{
            event_type = (char *) "SETGID";
            struct SetgidEvent *e = (struct SetgidEvent *) data;
            if (my_args_user.if_output_to_file) {
                if (my_args_user.if_output_as_json) {
                    //output the record as json
                    fprintf(output_user, "{"
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
                else if (my_args_user.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_user, "{"
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
                    fprintf(output_user, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setgidArguments.gid);
                }
            }
                //output to console/shell
            else {
                if (my_args_user.if_output_as_json) {
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
                else if (my_args_user.if_output_as_origin) {
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
            event_type = (char *) "SETUID";
            struct SetuidEvent *e = (struct SetuidEvent *) data;
            if (my_args_user.if_output_to_file) {
                if (my_args_user.if_output_as_json) {
                    //output the record as json
                    fprintf(output_user, "{"
                                        "\"Timestamp\":%ld,"
                                        "\"EventName\":\"%s\", "
                                        "\"ProcessName\":\"%s\", "
                                        "\"ProcessID\":%d, "
                                        "\"ThreadID\":%d, "
                                        "\"ProcessType\":\"%s\", "
                                        "\"Arguments\":{"
                                        "\"uid\":%d"
                                        "\"count\":%d}"
                                        "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setuidArguments.uid,
                            e->setuidArguments.count);
                } 
                else if (my_args_user.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_user, "{"
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
                           "\"uid\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setuidArguments.uid);
                } 
                else {
                    fprintf(output_user, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setuidArguments.uid,
                            e->setuidArguments.count);
                }
            }
                //output to console/shell
            else {
                if (my_args_user.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"uid\":%d"
                                                                   "\"count\":%d}"
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setuidArguments.uid,
                           e->setuidArguments.count);
                } 
                else if (my_args_user.if_output_as_origin) {
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
                           "\"uid\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setuidArguments.uid);
                }
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->setuidArguments.uid,
                           e->setuidArguments.count);

                }
            }
            break;
        }
        case EVENT_SETREGID:{
            event_type = (char *) "SETREGID";
            struct SetregidEvent *e = (struct SetregidEvent *) data;
            if (my_args_user.if_output_to_file) {
                if (my_args_user.if_output_as_json) {
                    //output the record as json
                    fprintf(output_user, "{"
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
                else if (my_args_user.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_user, "{"
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
                           "\"egid\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setregidArguments.setregid_rgid,
                           e->setregidArguments.setregid_egid);
                }
                else {
                    fprintf(output_user, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setregidArguments.setregid_rgid,
                            e->setregidArguments.setregid_egid);
                }
            }
                //output to console/shell
            else {
                if (my_args_user.if_output_as_json) {
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
                else if (my_args_user.if_output_as_origin) {
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
                           "\"egid\":%d}} "
                           "}\n",
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
            event_type = (char *) "SETRESGID";
            struct SetresgidEvent *e = (struct SetresgidEvent *) data;
            if (my_args_user.if_output_to_file) {
                if (my_args_user.if_output_as_json) {
                    //output the record as json
                    fprintf(output_user, "{"
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
                else if (my_args_user.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_user, "{"
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
                           "\"sgid\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setresgidArguments.setresgid_rgid,
                           e->setresgidArguments.setresgid_egid,
                           e->setresgidArguments.setresgid_sgid);
                }
                else {
                    fprintf(output_user, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setresgidArguments.setresgid_rgid,
                            e->setresgidArguments.setresgid_egid,
                            e->setresgidArguments.setresgid_sgid);
                }
            }
                //output to console/shell
            else {
                if (my_args_user.if_output_as_json) {
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
                else if (my_args_user.if_output_as_origin) {
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
                           "\"sgid\":%d}} "
                           "}\n",
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
            event_type = (char *) "SETRESUID";
            struct SetresuidEvent *e = (struct SetresuidEvent *) data;
            if (my_args_user.if_output_to_file) {
                if (my_args_user.if_output_as_json) {
                    //output the record as json
                    fprintf(output_user, "{"
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
                else if (my_args_user.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_user, "{"
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
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setresuidArguments.setresuid_ruid,
                           e->setresuidArguments.setresuid_euid,
                           e->setresuidArguments.setresuid_suid);
                }
                else {
                    fprintf(output_user, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setresuidArguments.setresuid_ruid,
                            e->setresuidArguments.setresuid_euid,
                            e->setresuidArguments.setresuid_suid);
                }
            }
                //output to console/shell
            else {
                if (my_args_user.if_output_as_json) {
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
                else if (my_args_user.if_output_as_origin) {
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
                           "\"suid\":%d}} "
                           "}\n",
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
            event_type = (char *) "SETREUID";
            struct SetreuidEvent *e = (struct SetreuidEvent *) data;
            if (my_args_user.if_output_to_file) {
                if (my_args_user.if_output_as_json) {
                    //output the record as json
                    fprintf(output_user, "{"
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
                else if (my_args_user.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_user, "{"
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
                           "\"euid\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->setreuidArguments.setreuid_ruid,
                           e->setreuidArguments.setreuid_euid);
                }
                else {
                    fprintf(output_user, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->setreuidArguments.setreuid_ruid,
                            e->setreuidArguments.setreuid_euid);
                }
            }
                //output to console/shell
            else {
                if (my_args_user.if_output_as_json) {
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
                else if (my_args_user.if_output_as_origin) {
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
                           "\"euid\":%d}} "
                           "}\n",
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
        case EVENT_NET_DEV_XMIT:{
            event_type = (char *) "EVENT_NET_DEV_XMIT";
            struct NetdevxmitEvent *e = (struct NetdevxmitEvent *) data;
            if (my_args_user.if_output_to_file) {
                if (my_args_user.if_output_as_json) {
                    //output the record as json
                    fprintf(output_user, "{"
                                         "\"Timestamp\":%ld,"
                                         "\"EventName\":\"%s\", "
                                         "\"ProcessName\":\"%s\", "
                                         "\"ProcessID\":%d, "
                                         "\"ThreadID\":%d, "
                                         "\"ProcessType\":\"%s\", "
                                         "\"Arguments\":{"
                                         "\"len\":%d} "
                                         "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->netdevxmitArguments.len);
                } 
                else if (my_args_user.if_output_as_origin) {
                    //output the record as origin
                    fprintf(output_user, "{"
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
                           "\"len\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
 e->netdevxmitArguments.len);
                }  
                else {
                    fprintf(output_user, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                             e->netdevxmitArguments.len);
                }
            }
                //output to console/shell
            else {
                if (my_args_user.if_output_as_json) {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"len\":%d} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->netdevxmitArguments.len);
                }
                else if (my_args_user.if_output_as_origin) {
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
                           "\"len\":%d}} "
                           "}\n",
                           e->event.comm,e->event.pid,e->event.ppid,process_type,getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type,  
                           e->netdevxmitArguments.len);
                }  
                else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->netdevxmitArguments.len,
                            e->netdevxmitArguments.protocol);
                }
            }
            break;
        }

    }
    return 0;
}

//communicate with main.c
int test_user(Args args) {
printf("Error polling perf buffer: %d\n", args.if_output_as_origin);
printf("Error polling perf buffer: %d\n", args.if_output_as_json);
    my_args_user = args;
    std::cerr << "=============test=============" << std::endl << std::endl;
    printf("=========================test=========================\n");
    if (my_args_user.if_output_to_file) {
        output_user = fopen(my_args_user.output_file.c_str(), "w");
        if (output_user == NULL) {
            fprintf(stderr, "please enter a valid file name/path\n");
            return 1;
        }
    }
    struct ring_buffer *rb = NULL;
    struct user_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Load and verify BPF application */
    skel = user_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    printf("=========================Open=========================\n");

    /* Load & verify BPF programs */
    err = user_bpf__load(skel);
    if (err) {
    	 fprintf(stderr, "Failed to load BPF skeleton: %d\n", libbpf_strerror(err,NULL,0));
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    printf("=========================Load=========================\n");

    /* Attach tracepoints */
    err = user_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("=========================Attach=========================\n");

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_user_event, NULL, NULL);//handle_file_event处理数据
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("=========================Ring Buffer=========================\n");

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args_user.if_output_as_json&&!my_args_user.if_output_as_origin) {
        if (my_args_user.if_output_to_file) {
            fprintf(output_user, "%-20s %-10s %-32s %-7s %-7s %15s\n",
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
            fclose(output_user);
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            fclose(output_user);
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    user_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}

