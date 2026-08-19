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
#include "../../include/filter.h"
#include "../../include/snapshot.h"
#include "../../include/basic.h"
#include "../../include/output_sink.h"
/* blazesym.h's own stdint/stddef includes are commented out upstream (g++ needs
 * them supplied first -- kellect-ebpf skill §10); runtime link: -lrt -ldl -lm. */
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "../../include/blazesym.h"

struct Args my_args_process;

FILE *output_process;

static volatile bool exiting = false;

/* Phase 2 #4 Step 2: user stack symbolization (blazesym). EXECVE's user stack
 * lives in the parent's address space (fork copy, identical layout until exec);
 * by consumption time the event's own pid has already swapped its mappings, so
 * symbolization goes via ppid -- by pid it would misattribute (wrong symbols,
 * worse than failure). Root context required: yama/ptrace_scope=1 blocks
 * /proc/<pid>/map_files for non-root (spike 2026-08-22). */
static blaze_symbolizer *g_symbolizer = NULL;
static struct bpf_map *g_stack_map = NULL;

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

/* Sanitize symbol names for JSON output: ELF symbol names may contain quotes,
 * backslashes, or control bytes -- a crafted name must not break or inject
 * into the JSON lines consumed downstream (security-review 2026-08-22). */
static void json_escape_into(char *dst, size_t dstsz, const char *src) {
    size_t o = 0;
    for (size_t i = 0; src != NULL && src[i] != '\0' && o + 6 < dstsz; i++) {
        unsigned char c = (unsigned char) src[i];
        if (c == '"' || c == '\\') {
            dst[o++] = '\\';
            dst[o++] = (char) c;
        } else if (c < 0x20) {
            o += (size_t) snprintf(dst + o, dstsz - o, "\\u%04x", c);
        } else {
            dst[o++] = (char) c;
        }
    }
    dst[o] = '\0';
}

/* pid-reuse guard (security-review 2026-08-22): by consumption time the ppid
 * may already belong to an unrelated recycled process -- symbolizing against
 * its mappings would silently misattribute. The event comm is the parent's
 * comm as inherited at fork (bpf_get_current_comm runs before exec replaces
 * it), so cross-checking /proc/<ppid>/comm catches most reuse/exits. */
static bool ppid_comm_matches(int ppid, const char *event_comm) {
    if (ppid <= 0) return false;
    char path[32];
    char comm[TASK_COMM_LEN];
    snprintf(path, sizeof(path), "/proc/%d/comm", ppid);
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;
    size_t n = fread(comm, 1, sizeof(comm) - 1, f);
    fclose(f);
    comm[n] = '\0';
    for (size_t i = 0; i < n; i++) {
        if (comm[i] == '\n') comm[i] = '\0';
    }
    return strncmp(comm, event_comm, TASK_COMM_LEN) == 0;
}

/* EXECVE 的 event.ppid 实为 task->tgid（触发进程自身，上游 BPF 端命名错位），
 * 不是父进程。exec 不改变 real_parent 关系，从 /proc/<tgid>/status 的
 * PPid: 行取真实父 pid；进程已退出/不可读返回 -1（调用方回退裸 IP）。 */
static pid_t real_parent_of(pid_t pid) {
    if (pid <= 0) return -1;
    char path[32];
    char line[128];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    pid_t ppid = -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = (pid_t) strtol(line + 5, NULL, 10); /* strtol 自跳前导空白 */
            break;
        }
    }
    fclose(f);
    return ppid;
}

/* Phase 2 #4 Step 2: build the symbolized user stack for an EXECVE event.
 * json gets the array body ("sym+0xoff" / "0xaddr" entries, brackets added by
 * the caller); txt gets a comma list with control chars blanked. Every
 * fallback (no symbolizer, stack id evicted, ppid reuse/mismatch, resolve
 * failure) still emits the raw IPs -- addresses keep forensic value for
 * offline analysis. v1 caps output at 8 frames.
 * Returns the real parent pid used (or available) for output: the BPF-captured
 * event-time value is preferred (no race against short-lived children); the
 * /proc status lookup is only a fallback for a failed CO-RE read (field == 0). */
#define MAX_USER_STACK_FRAMES 127 /* mirrors stack_trace_t.ips[127] in process.bpf.c (value 1016B) */
#define USER_STACK_OUT_FRAMES 8

static pid_t build_user_stack(const struct ExecveEvent *e, char *json, size_t jsz,
                             char *txt, size_t tsz) {
    json[0] = '\0';
    txt[0] = '\0';
    pid_t real_ppid = e->event.real_parent_tgid; /* common header since 差距 #4 */
    if (real_ppid <= 0) {
        real_ppid = real_parent_of(e->event.ppid);
    }
    if (e->execveArguments.user_stack_id < 0 || g_stack_map == NULL) return real_ppid;

    unsigned long long ips[MAX_USER_STACK_FRAMES];
    int key = e->execveArguments.user_stack_id;
    if (bpf_map__lookup_elem(g_stack_map, &key, sizeof(key), ips, sizeof(ips), 0) != 0) return real_ppid; /* id evicted (ABA) */

    size_t n = 0;
    while (n < MAX_USER_STACK_FRAMES && ips[n] != 0) n++; /* unused frames are zero */
    if (n == 0) return real_ppid;

    const struct blaze_result *res = NULL;
    if (g_symbolizer != NULL && real_ppid > 0 && ppid_comm_matches(real_ppid, e->event.comm)) {
        struct blaze_symbolize_src_process src;
        memset(&src, 0, sizeof(src));
        src.pid = (uint32_t) real_ppid;
        src.debug_syms = false;
        res = blaze_symbolize_process_virt_addrs(g_symbolizer, &src,
                                                 (const uintptr_t *) ips, n);
    }

    size_t jo = 0, to = 0;
    for (size_t i = 0; i < n && i < USER_STACK_OUT_FRAMES; i++) {
        char frame_json[160], frame_txt[128], esc[96];
        const struct blaze_sym *s = (res != NULL && i < res->cnt) ? &res->syms[i] : NULL;
        if (s != NULL && s->name != NULL) {
            json_escape_into(esc, sizeof(esc), s->name);
            snprintf(frame_json, sizeof(frame_json), "\"%s+0x%zx\"", esc, s->offset);
            snprintf(frame_txt, sizeof(frame_txt), "%s+0x%zx", s->name, s->offset);
            for (char *p = frame_txt; *p != '\0'; p++) {
                if ((unsigned char) *p < 0x20) *p = ' ';
            }
        } else {
            snprintf(frame_json, sizeof(frame_json), "\"0x%llx\"", ips[i]);
            snprintf(frame_txt, sizeof(frame_txt), "0x%llx", ips[i]);
        }
        int w = snprintf(json + jo, jsz - jo, "%s%s", jo != 0 ? "," : "", frame_json);
        if (w < 0 || (size_t) w >= jsz - jo) break;
        jo += (size_t) w;
        w = snprintf(txt + to, tsz - to, "%s%s", to != 0 ? "," : "", frame_txt);
        if (w < 0 || (size_t) w >= tsz - to) break;
        to += (size_t) w;
    }
    if (res != NULL) blaze_result_free(res);
    return real_ppid;
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

    /**
     * v1 userspace filter: include (union) + exclude (drop-on-match)
     */
    if (event_filtered_out(e->pid, e->comm, &my_args_process)) {
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"ParentPID\":%d, "
                                            "\"ParentPName\":\"%s\","
                                            "\"ChildPID\":%d,"
                                            "\"ChildPName\":\"%s\"} "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"ParentPID\":%d, "
                           "\"ParentPName\":\"%s\","
                           "\"ChildPID\":%d,"
                           "\"ChildPName\":\"%s\"} "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"OldPID\":%d, "
                                            "\"PID\":%d,"
                                            "\"Executable\":\"%s\","
                                            "\"UserStackId\":%d,"
                                            "\"KernStackId\":%d}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type, e->event.pcomm,
                            e->execArguments.old_pid,
                            e->execArguments.pid,
                            e->event.filename,
                            e->execArguments.user_stack_id,
                            e->execArguments.kern_stack_id);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s %-8d %-8d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execArguments.old_pid,
                            e->execArguments.pid,
                            e->event.filename,
                            e->execArguments.user_stack_id,
                            e->execArguments.kern_stack_id);
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"OldPID\":%d, "
                           "\"PID\":%d,"
                           "\"Executable\":\"%s\","
                           "\"UserStackId\":%d,"
                           "\"KernStackId\":%d}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
                           e->execArguments.old_pid,
                           e->execArguments.pid,
                           e->event.filename,
                           e->execArguments.user_stack_id,
                           e->execArguments.kern_stack_id);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-7d %-20s %-8d %-8d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->execArguments.old_pid,
                           e->execArguments.pid,
                           e->event.filename,
                           e->execArguments.user_stack_id,
                           e->execArguments.kern_stack_id);
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"CloneFlags\":%ld, "
                                            "\"NewSP\":%ld,"
                                            "\"TLS\":%ld,"
                                            "\"ParentTidPtr\":%p,"
                                            "\"ChildTidPtr\":%p"
                                            "}} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"CloneFlags\":%ld, "
                           "\"NewSP\":%ld,"
                           "\"TLS\":%ld,"
                           "\"ParentTidPtr\":%p,"
                           "\"ChildTidPtr\":%p"
                           "}} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Exit_code\":%d, "
                                            "\"PID\":%d, "
                                            "\"ExitPName\":%s,"
                                            "\"Priority\":%d}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Exit_code\":%d, "
                           "\"PID\":%d, "
                           "\"ExitPName\":%s,"
                           "\"Priority\":%d}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                            "\"F1\":%d, "
                            "\"F2\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                           "\"Flags\":%d, "
                                            "\"F1\":%d, "
                                            "\"F2\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                            "\"Flags\":%d, "
                             "\"F1\":%d, "
                            "\"F2\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                            "\"pid\":%d, "
                            "\"sig\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"size\":%d,"
                                            "}} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"size\":%d,"
                           "}} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
            /* Phase 2 #4 Step 2: symbolized user stack via the real parent (caller's space) */
            char us_json[512], us_txt[192];
            pid_t real_ppid = build_user_stack(e, us_json, sizeof(us_json), us_txt, sizeof(us_txt));
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"RealParentPid\":%d,"
                                            "\"Filename\":\"%s\","
                                            "\"UserStackId\":%d,"
                                            "\"KernStackId\":%d,"
                                            "\"UserStack\":[%s]}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
                            real_ppid > 0 ? real_ppid : 0,
                            e->execveArguments.filename,
                            e->execveArguments.user_stack_id,
                            e->execveArguments.kern_stack_id,
                            us_json);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-8d %-8d %.60s \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execveArguments.filename,
                            e->execveArguments.user_stack_id,
                            e->execveArguments.kern_stack_id,
                            us_txt);
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"RealParentPid\":%d,"
                           "\"Filename\":\"%s\","
                           "\"UserStackId\":%d,"
                           "\"KernStackId\":%d,"
                           "\"UserStack\":[%s]}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
                           real_ppid > 0 ? real_ppid : 0,
                           e->execveArguments.filename,
                           e->execveArguments.user_stack_id,
                           e->execveArguments.kern_stack_id,
                           us_json);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-10s %-8d %-8d %.60s \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                           e->execveArguments.filename,
                           e->execveArguments.user_stack_id,
                           e->execveArguments.kern_stack_id,
                           us_txt);
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"FD\":%d, "
                                            "\"Filename\":\"%s\","
                                            "\"flags\":%d, "
                                            "\"UserStackId\":%d,"
                                            "\"KernStackId\":%d}"
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags,
                            e->execveatArguments.user_stack_id,
                            e->execveatArguments.kern_stack_id);
                } else {
                    fprintf(output_process, "%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-8d %-8d \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                            e->event.ppid, process_type,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags,
                            e->execveatArguments.user_stack_id,
                            e->execveatArguments.kern_stack_id);
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"FD\":%d, "
                           "\"Filename\":\"%s\","
                           "\"flags\":%d, "
                           "\"UserStackId\":%d,"
                           "\"KernStackId\":%d}"
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags,
                            e->execveatArguments.user_stack_id,
                            e->execveatArguments.kern_stack_id);
                } else {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-7d %-10s %-7d %-8d %-8d \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type,
                            e->execveatArguments.fd,
                            e->execveatArguments.filename,
                            e->execveatArguments.flags,
                            e->execveatArguments.user_stack_id,
                            e->execveatArguments.kern_stack_id);
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Code\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Code\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Request\":%ld, "
                                            "\"Pid\":%ld, "
                                            "\"Addr\":%ld, "
                                            "\"Data\":%ld, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                            "\"Request\":%ld, "
                            "\"Pid\":%ld, "
                            "\"Addr\":%ld, "
                            "\"Data\":%ld, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                             "\"tgid\":%d, "
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                            "\"tgid\":%d, "
                            "\"pid\":%d, "
                            "\"sig\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                           "\"pid\":%d, "
                                           "\"sig\":%d, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                            "\"pid\":%d, "
                            "\"sig\":%d, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm);
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm);
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Addr\":%ld, "
                                            "\"Len\":%ld, "
                                            "\"Prot\":%ld, "
                                            "\"Flags\":%ld, "
                                            "\"Fd\":%ld, "
                                            "\"Off\":%ld, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                             "\"Addr\":%ld, "
                            "\"Len\":%ld, "
                             "\"Prot\":%ld, "
                            "\"Flags\":%ld, "
                            "\"Fd\":%ld, "
                             "\"Off\":%ld, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
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
                                            "\"ParentName\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Addr\":%ld, "
                                            "\"Len\":%zu, "
                                            "\"Prot\":%ld, "
                                            "}\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type, e->event.pcomm,
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
                           "\"ParentName\":\"%s\", "
                           "\"Arguments\":{"
                            "\"Addr\":%ld, "
                            "\"Len\":%zu, "
                             "\"Prot\":%ld, "
                           "}\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid,
                           e->event.ppid, process_type, e->event.pcomm,
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
        output_process = create_output_sink(&my_args_process);
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

    /* Phase 2 #4 Step 2: stack map handle + blazesym symbolizer. Must stay in this
     * root process (spike 2026-08-22): yama/ptrace_scope=1 denies
     * /proc/<pid>/map_files to non-root, so symbolization cannot be offloaded
     * to a non-root forwarder. NULL symbolizer is non-fatal -- UserStack just
     * falls back to raw IPs. */
    g_stack_map = skel->maps.stack_map;
    g_symbolizer = blaze_symbolizer_new();
    if (g_symbolizer == NULL) {
        fprintf(stderr, "warn: blaze_symbolizer_new failed, UserStack falls back to raw IPs\n");
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

    walk_proc_snapshot(output_process, my_args_process.if_output_to_file, &my_args_process, "DCStart");

    while (!exiting) {
        err = ring_buffer__poll(rb, 10);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    walk_proc_snapshot(output_process, my_args_process.if_output_to_file, &my_args_process, "DCEnd");
    if (output_process != NULL) close_output_sink(output_process);

    cleanup:
    if (g_symbolizer != NULL) {
        blaze_symbolizer_free(g_symbolizer);
        g_symbolizer = NULL;
    }
    g_stack_map = NULL;
    ring_buffer__free(rb);
    process_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
