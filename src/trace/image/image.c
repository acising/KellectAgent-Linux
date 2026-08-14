// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phase 2 #2: image/executable load detection — userspace side.
//
// Receives ImageLoadEvent from the BPF ringbuf, resolves fd → file path via
// /proc/<pid>/fd/<fd> readlink (bpf_d_path is unavailable in tracepoint
// programs), with a /proc/<pid>/maps Addr-match fallback for the common
// loader case where the fd is closed before we consume the event, and prints
// the 4-branch output (file/console × json/text).

/* g++ predefines _GNU_SOURCE as 1 -- a bare #define here is a distinct
 * token sequence and triggers -Wbuiltin-macro-redefined style warnings on
 * gcc 11+. Guard it like output_sink.h does. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "../../include/image.h"
#include "image.skel.h"
#include "../../include/arg_parser.h"
#include "../../include/filter.h"
#include "../../include/snapshot.h"
#include "../../include/basic.h"
#include "../../include/output_sink.h"

struct Args my_args_image;

FILE *output_image;

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (my_args_image.if_debug_mode) {
        return vfprintf(stderr, format, args);
    } else {
        return 0;
    }
}

static void handle_signal(int signal) {
    exiting = true;
}

/*
 * Phase 2 #2: maps fallback — resolve the path from /proc/<pid>/maps after the
 * fd is already closed.
 *
 * Loader pattern (ld.so / dlopen) opens a lib, mmaps its segments
 * (MAP_FIXED → returned addr == requested addr), then closes the fd — often
 * before our userspace consumes the ringbuf events. readlink on the fd then
 * fails, but the MAPPING persists in /proc/<pid>/maps for the process
 * lifetime. Match the event's Addr against maps' start-end ranges to recover
 * the backing file path.
 *
 * Limits: non-MAP_FIXED addrs are hints (mapping may live elsewhere → no
 * match); process exit removes maps entirely (→ "<closed>"). Only file-backed
 * lines carry a '/' — anon/[heap]/[stack] lines have no pathname.
 */
/* Three-way result: distinguishes an anonymous-region hit (meaningful for
 * mprotect events — executable rights on heap/JIT memory) from a plain miss. */
enum map_resolve {
    MAP_PATH_FOUND,   /* addr matched a file-backed mapping; path written to out */
    MAP_ANON_REGION,  /* addr matched an anon/[heap]/[stack] mapping — no path  */
    MAP_MISS          /* maps unreadable (process exited) or no range contains addr */
};

static enum map_resolve resolve_path_from_maps(int pid, unsigned long addr, char *out, size_t out_sz)
{
    char maps_path[48];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        return MAP_MISS;
    }

    char line[512];
    enum map_resolve result = MAP_MISS;
    while (fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
            continue;
        }
        if (addr < start || addr >= end) {
            continue;
        }
        /* pathname is the only field starting with '/' (perms/offset/dev never
         * contain one); its absence means an anon/[heap]/[stack] mapping */
        const char *p = strchr(line, '/');
        if (!p) {
            result = MAP_ANON_REGION;  /* matched a non-file mapping */
            break;
        }
        size_t len = strcspn(p, " \t\n");
        if (len >= out_sz) {
            len = out_sz - 1;
        }
        memcpy(out, p, len);
        out[len] = '\0';
        result = MAP_PATH_FOUND;
        break;
    }
    fclose(f);
    return result;
}

/*
 * Phase 2 #2: resolve an mmap fd to the backing file path.
 *
 * bpf_d_path is only usable from BPF_PROG_TYPE_TRACING (fentry/fexit/lsm), so
 * we cannot capture the path inside the tracepoint handler. Instead the BPF
 * side stores the raw fd and we resolve it here by readlink'ing
 * /proc/<pid>/fd/<fd>.
 *
 * fd == -1 (MAP_ANONYMOUS) → "<anonymous>" (JIT/packer/shellcode; EDR-relevant)
 * readlink succeeds        → real path
 * readlink fails, mapping alive → path recovered from /proc/<pid>/maps
 *                               (loader closed the fd; MAP_FIXED addrs match)
 * otherwise (process exited / mmap failed) → "<closed>"
 */
static void resolve_image_path(int pid, int fd, unsigned long addr, char *out, size_t out_sz)
{
    if (fd < 0) {
        strncpy(out, "<anonymous>", out_sz - 1);
        out[out_sz - 1] = '\0';
        return;
    }

    char proc_link[64];
    snprintf(proc_link, sizeof(proc_link), "/proc/%d/fd/%d", pid, fd);

    ssize_t n = readlink(proc_link, out, out_sz - 1);
    if (n > 0) {
        out[n] = '\0';
        return;
    }

    /* fd gone (loader closed it) — the mapping may still be alive in maps */
    if (resolve_path_from_maps(pid, addr, out, out_sz) == MAP_PATH_FOUND) {
        return;
    }

    strncpy(out, "<closed>", out_sz - 1);
    out[out_sz - 1] = '\0';
}

/*
 * Phase 2 #2 Stage 2: resolve an mprotect target by addr alone (no fd).
 *
 * mprotect acts on an existing mapping, so /proc/<pid>/maps always has the
 * answer while the process lives:
 *   file-backed mapping → real path (ld.so raising .so segments to R+X)
 *   anon/[heap]/[stack] → "<anonymous>" — RW->RWX on non-file memory is the
 *                        strongest injection signal, downstream rule bait
 *   process exited      → "<closed>" (principle limit, same as Image_Load)
 */
static void resolve_mprotect_path(int pid, unsigned long addr, char *out, size_t out_sz)
{
    switch (resolve_path_from_maps(pid, addr, out, out_sz)) {
    case MAP_PATH_FOUND:
        return;
    case MAP_ANON_REGION:
        strncpy(out, "<anonymous>", out_sz - 1);
        out[out_sz - 1] = '\0';
        return;
    case MAP_MISS:
    default:
        strncpy(out, "<closed>", out_sz - 1);
        out[out_sz - 1] = '\0';
        return;
    }
}

static int handle_image_event(void *ctx, void *data, size_t data_sz) {
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
    if (strcmp("gnome-terminal-", e->comm) == 0 && my_args_image.if_output_to_file == false) {
        return 0;
    }

    /**
     * v1 userspace filter: include (union) + exclude (drop-on-match)
     */
    if (event_filtered_out(e->pid, e->comm, &my_args_image)) {
        return 0;
    }

    char *event_type;

    switch (e->event_type) {
        case EVENT_IMAGE_LOAD: {
            event_type = (char *) "Image_Load";
            struct ImageLoadEvent *e = (struct ImageLoadEvent *) data;

            /* Phase 2 #2: resolve fd → path in userspace (see resolve_image_path) */
            char path[PATH_MAX];
            resolve_image_path(e->event.pid, e->imageLoadArguments.fd,
                               e->imageLoadArguments.addr, path, sizeof(path));

            if (my_args_image.if_output_to_file)
            {
                if (my_args_image.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_image, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Addr\":%lu, "
                                            "\"Len\":%lu, "
                                            "\"Prot\":%lu, "
                                            "\"Flags\":%lu, "
                                            "\"Fd\":%d, "
                                            "\"Off\":%lu, "
                                            "\"Path\":\"%s\"} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageLoadArguments.addr,
                            e->imageLoadArguments.len,
                            e->imageLoadArguments.prot,
                            e->imageLoadArguments.flags,
                            e->imageLoadArguments.fd,
                            e->imageLoadArguments.off,
                            path);
                }
                else
                {
                    fprintf(output_image, "%-20ld %-10s %-32s %-7d %-7d %-10s %-12lu %-10lu %-5lu %-10lu %-5d %-10lu %-40s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageLoadArguments.addr,
                            e->imageLoadArguments.len,
                            e->imageLoadArguments.prot,
                            e->imageLoadArguments.flags,
                            e->imageLoadArguments.fd,
                            e->imageLoadArguments.off,
                            path);
                }
            }
            /**
             * output to console/shell
             */
            else
            {
                if (my_args_image.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Addr\":%lu, "
                           "\"Len\":%lu, "
                           "\"Prot\":%lu, "
                           "\"Flags\":%lu, "
                           "\"Fd\":%d, "
                           "\"Off\":%lu, "
                           "\"Path\":\"%s\"} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageLoadArguments.addr,
                           e->imageLoadArguments.len,
                           e->imageLoadArguments.prot,
                           e->imageLoadArguments.flags,
                           e->imageLoadArguments.fd,
                           e->imageLoadArguments.off,
                           path);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-12lu %-10lu %-5lu %-10lu %-5d %-10lu %-40s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageLoadArguments.addr,
                           e->imageLoadArguments.len,
                           e->imageLoadArguments.prot,
                           e->imageLoadArguments.flags,
                           e->imageLoadArguments.fd,
                           e->imageLoadArguments.off,
                           path);
                }
            }
            break;
        }
        case EVENT_IMAGE_MPROTECT: {
            event_type = (char *) "Image_Mprotect";
            struct ImageMprotectEvent *e = (struct ImageMprotectEvent *) data;

            /* Stage 2: resolve by addr alone — "<anonymous>" here is the
             * strongest injection signal (RW->RWX on non-file memory). */
            char path[PATH_MAX];
            resolve_mprotect_path(e->event.pid, e->imageMprotectArguments.addr, path, sizeof(path));

            if (my_args_image.if_output_to_file)
            {
                if (my_args_image.if_output_as_json)
                {
                    /**
                     * output the record as json
                     */
                    fprintf(output_image, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Addr\":%lu, "
                                            "\"Len\":%lu, "
                                            "\"Prot\":%lu, "
                                            "\"Path\":\"%s\"} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageMprotectArguments.addr, e->imageMprotectArguments.len,
                            e->imageMprotectArguments.prot, path);
                }
                else
                {
                    fprintf(output_image, "%-20ld %-10s %-32s %-7d %-7d %-10s %-12lu %-10lu %-5lu %-40s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageMprotectArguments.addr, e->imageMprotectArguments.len,
                            e->imageMprotectArguments.prot, path);
                }
            }
            /** output to console/shell */
            else
            {
                if (my_args_image.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Addr\":%lu, "
                           "\"Len\":%lu, "
                           "\"Prot\":%lu, "
                           "\"Path\":\"%s\"} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageMprotectArguments.addr, e->imageMprotectArguments.len,
                           e->imageMprotectArguments.prot, path);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-12lu %-10lu %-5lu %-40s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageMprotectArguments.addr, e->imageMprotectArguments.len,
                           e->imageMprotectArguments.prot, path);
                }
            }
            break;
        }
        case EVENT_IMAGE_UNLOAD: {
            event_type = (char *) "Image_Unload";
            struct ImageUnloadEvent *e = (struct ImageUnloadEvent *) data;

            /* 差距 #3: munmap was caught at sys_enter (mapping still alive then),
             * but may already be torn down at consumption — same three-state
             * addr-based resolution as mprotect. */
            char path[PATH_MAX];
            resolve_mprotect_path(e->event.pid, e->imageUnloadArguments.addr, path, sizeof(path));

            if (my_args_image.if_output_to_file)
            {
                if (my_args_image.if_output_as_json)
                {
                    fprintf(output_image, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Addr\":%lu, "
                                            "\"Len\":%lu, "
                                            "\"Path\":\"%s\"} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageUnloadArguments.addr, e->imageUnloadArguments.len, path);
                }
                else
                {
                    fprintf(output_image, "%-20ld %-10s %-32s %-7d %-7d %-10s %-12lu %-10lu %-40s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageUnloadArguments.addr, e->imageUnloadArguments.len, path);
                }
            }
            /** output to console/shell */
            else
            {
                if (my_args_image.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Addr\":%lu, "
                           "\"Len\":%lu, "
                           "\"Path\":\"%s\"} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageUnloadArguments.addr, e->imageUnloadArguments.len, path);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-12lu %-10lu %-40s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageUnloadArguments.addr, e->imageUnloadArguments.len, path);
                }
            }
            break;
        }
        case EVENT_IMAGE_MODULE_LOAD: {
            event_type = (char *) "Module_Load";
            struct ImageModuleLoadEvent *e = (struct ImageModuleLoadEvent *) data;

            if (my_args_image.if_output_to_file)
            {
                if (my_args_image.if_output_as_json)
                {
                    fprintf(output_image, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Name\":\"%s\", "
                                            "\"Taints\":%u} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageModuleLoadArguments.name, e->imageModuleLoadArguments.taints);
                }
                else
                {
                    fprintf(output_image, "%-20ld %-10s %-32s %-7d %-7d %-10s %-20s %-10u\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageModuleLoadArguments.name, e->imageModuleLoadArguments.taints);
                }
            }
            /** output to console/shell */
            else
            {
                if (my_args_image.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Name\":\"%s\", "
                           "\"Taints\":%u} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageModuleLoadArguments.name, e->imageModuleLoadArguments.taints);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-20s %-10u\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageModuleLoadArguments.name, e->imageModuleLoadArguments.taints);
                }
            }
            break;
        }
        case EVENT_IMAGE_MODULE_UNLOAD: {
            event_type = (char *) "Module_Unload";
            struct ImageModuleUnloadEvent *e = (struct ImageModuleUnloadEvent *) data;

            if (my_args_image.if_output_to_file)
            {
                if (my_args_image.if_output_as_json)
                {
                    fprintf(output_image, "{"
                                            "\"Timestamp\":%ld,"
                                            "\"EventName\":\"%s\", "
                                            "\"ProcessName\":\"%s\", "
                                            "\"ProcessID\":%d, "
                                            "\"ThreadID\":%d, "
                                            "\"ProcessType\":\"%s\", "
                                            "\"Arguments\":{"
                                            "\"Name\":\"%s\"} "
                                            "} \n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageModuleUnloadArguments.name);
                }
                else
                {
                    fprintf(output_image, "%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                            getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                            e->imageModuleUnloadArguments.name);
                }
            }
            /** output to console/shell */
            else
            {
                if (my_args_image.if_output_as_json)
                {
                    printf("{"
                           "\"Timestamp\":%ld,"
                           "\"EventName\":\"%s\", "
                           "\"ProcessName\":\"%s\", "
                           "\"ProcessID\":%d, "
                           "\"ThreadID\":%d, "
                           "\"ProcessType\":\"%s\", "
                           "\"Arguments\":{"
                           "\"Name\":\"%s\"} "
                           "} \n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageModuleUnloadArguments.name);
                }
                else
                {
                    printf("%-20ld %-10s %-32s %-7d %-7d %-10s %-20s\n",
                           getCurrentTimestamp(TIMESTAMP_MICROSECOND), event_type, e->event.comm, e->event.pid, e->event.ppid, process_type,
                           e->imageModuleUnloadArguments.name);
                }
            }
            break;
        }
    }

    return 0;
}

int test_image(Args args) {
    my_args_image = args;

    if (my_args_image.if_output_to_file) {
        output_image = create_output_sink(&my_args_image);
        if (output_image == NULL) {
            fprintf(stderr, "please enter a valid file name/path\n");
            return 1;
        }
    }

    struct ring_buffer *rb = NULL;
    struct image_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = image_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = image_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    err = image_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_image_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /**
     * if the output format is json, do not print the title.
     */
    if (!my_args_image.if_output_as_json) {
        if (my_args_image.if_output_to_file) {
            fprintf(output_image, "%-20s %-10s %-32s %-7s %-7s %10s\n",
                    "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        } else {
            printf("%-20s %-10s %-32s %-7s %-7s %10s\n",
                   "TimeStamp", "EventName", "COMM", "PID", "PPID", "PROCESS/THREAD");
        }
    }

    walk_proc_snapshot(output_image, my_args_image.if_output_to_file, &my_args_image, "DCStart");

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

    walk_proc_snapshot(output_image, my_args_image.if_output_to_file, &my_args_image, "DCEnd");
    if (output_image != NULL) close_output_sink(output_image);

    cleanup:
    ring_buffer__free(rb);
    image_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
