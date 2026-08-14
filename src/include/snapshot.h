// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// DCStart/DCEnd process snapshot — userspace /proc walker.
//
// Linux has no kernel primitive that emits "existing process" events on BPF
// attach (unlike Windows ETW DC_START/DC_END, which the kernel enumerates).
// To close the same audit gap — processes already running before the collector
// started are invisible to live fork/exec tracepoints — this header snapshots
// /proc at collector start (DCStart) and stop (DCEnd).
//
// Design notes:
//  * Header-only static inline (mirrors filter.h); no Makefile change.
//  * Reuses the common `struct Event` envelope already defined per-loader
//    (all.h in all.c/conf.c, process.h in process.c — byte-identical copies).
//    => This header must be included AFTER the loader's all.h/process.h.
//  * Full-table semantics (Windows DCStart): ignores --pid/--comm filters.
//    Skips kellect itself (getpid()) and kernel threads (no /proc/<pid>/exe).
//  * Synthetic rows are printed directly — they do NOT ride the ringbuf
//    callback, so no enum/struct/switch changes are needed.
#ifndef KELLECT_LINUX_SNAPSHOT_H
#define KELLECT_LINUX_SNAPSHOT_H

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "arg_parser.h"   // struct Args
#include "basic.h"        // getCurrentTimestamp(), TIMESTAMP_MICROSECOND

// Print one synthetic DCStart/DCEnd row from the common Event envelope.
// Format mirrors the existing process events (FORK/EXEC/EXIT): key order is
// Timestamp, EventName, ProcessName(pid's comm), ProcessID, ThreadID(ppid),
// ProcessType, Arguments{...}. The same row is emitted to `out` (file) when
// to_file is true, otherwise to stdout — matching each loader's fprintf/printf
// split.
static inline void print_snapshot_event(FILE *out, bool to_file,
                                        const struct Args *args,
                                        const char *event_name,
                                        const struct Event *e) {
    FILE *sink = to_file ? out : stdout;
    long ts = getCurrentTimestamp(TIMESTAMP_MICROSECOND);
    const char *ptype = e->is_process ? "process" : "thread";

    if (args->if_output_as_json) {
        fprintf(sink, "{"
                "\"Timestamp\":%ld,"
                "\"EventName\":\"%s\", "
                "\"ProcessName\":\"%s\", "
                "\"ProcessID\":%d, "
                "\"ThreadID\":%d, "
                "\"ProcessType\":\"%s\", "
                "\"Arguments\":{"
                "\"Executable\":\"%s\", "
                "\"StartTime\":%llu, "
                "\"UID\":%u}"
                "} \n",
                ts, event_name, e->comm, e->pid, e->ppid, ptype,
                e->filename, e->start_time, e->uid);
    } else if (args->if_output_as_origin) {
        fprintf(sink, "{"
                "\"Timestamp\":%ld,"
                "\"EventName\":\"%s\", "
                "\"ProcessName\":\"%s\", "
                "\"ProcessID\":%d, "
                "\"ThreadID\":%d, "
                "\"ProcessType\":\"%s\", "
                "\"Arguments\":{"
                "\"Executable\":\"%s\", "
                "\"StartTime\":%llu, "
                "\"UID\":%u}}"
                "\n",
                ts, event_name, e->comm, e->pid, e->ppid, ptype,
                e->filename, e->start_time, e->uid);
    } else {
        // plain (raw) — column widths mirror FORK/EXEC/EXIT plain arms
        fprintf(sink, "%-20ld %-10s %-32s %-7d %-7d %-10s %-20s %-15llu %-7u \n",
                ts, event_name, e->comm, e->pid, e->ppid, ptype,
                e->filename, e->start_time, e->uid);
    }
}

// Walk /proc and emit one synthetic row per user process. Full-table: no
// include/exclude filtering (callers pass the same event_name "DCStart" or
// "DCEnd"). Tolerant of processes vanishing mid-walk (ENOENT/EACCES -> skip).
static inline void walk_proc_snapshot(FILE *out, bool to_file,
                                      const struct Args *args,
                                      const char *event_name) {
    DIR *d = opendir("/proc");
    if (!d) return;

    char path[256];
    char line[2048];
    struct dirent *de;
    const int self_pid = (int)getpid();

    while ((de = readdir(d)) != NULL) {
        // /proc entries for processes are purely numeric
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        if (pid <= 0 || pid == self_pid) continue;   // skip kellect itself

        // (a) /proc/<pid>/stat — comm sits inside the first '(' .. last ')'
        //     (comm may contain spaces/parens, so bracket-scan, don't sscanf).
        //     After ')': state ppid pgrp session tty_nr tpgid flags minflt
        //     cminflt majflt cmajflt utime stime cutime cstime priority nice
        //     num_threads itrealvalue starttime  (fields 3..22)
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char stat_line[2048];
        if (!fgets(stat_line, sizeof(stat_line), f)) { fclose(f); continue; }
        fclose(f);

        char *lp = strchr(stat_line, '(');
        char *rp = strrchr(stat_line, ')');
        if (!lp || !rp || rp <= lp) continue;

        char comm[TASK_COMM_LEN];
        size_t clen = (size_t)(rp - (lp + 1));
        if (clen >= sizeof(comm)) clen = sizeof(comm) - 1;
        memcpy(comm, lp + 1, clen);
        comm[clen] = '\0';

        int ppid = 0;
        unsigned long utime = 0, stime = 0;
        unsigned long long starttime = 0;
        /* Suppressed conversions carry NO length modifier (%*u, not %*lu):
         * GCC -Wformat flags "assignment suppression and length modifier
         * together" — the l is meaningless on a conversion that discards its
         * input, and %*u/%*lu parse identically. Stored conversions (%lu %lu
         * %llu) keep their modifiers. */
        int matched = sscanf(rp + 1,
            " %*c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %*d %*d %*d %*d %*d %*d %llu",
            &ppid, &utime, &stime, &starttime);
        if (matched < 4) continue;

        // (b) /proc/<pid>/status — Uid/Gid (real, effective) + ctxt switches
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        f = fopen(path, "r");
        if (!f) continue;
        unsigned int uid_r = 0, uid_e = 0, gid_r = 0, gid_e = 0;
        unsigned long nvcsw = 0, nivcsw = 0;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Uid:", 4) == 0)
                sscanf(line + 4, "%u %u", &uid_r, &uid_e);
            else if (strncmp(line, "Gid:", 4) == 0)
                sscanf(line + 4, "%u %u", &gid_r, &gid_e);
            else if (strncmp(line, "voluntary_ctxt_switches:", 24) == 0)
                sscanf(line + 24, "%lu", &nvcsw);
            else if (strncmp(line, "nonvoluntary_ctxt_switches:", 27) == 0)
                sscanf(line + 27, "%lu", &nivcsw);
        }
        fclose(f);

        // (c) /proc/<pid>/exe — executable realpath. Kernel threads / zombies
        //     have no exe symlink (readlink fails) -> skip, leaving only real
        //     user processes with a mapped executable image.
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        char exe[MAX_FILENAME_LEN];
        ssize_t n = readlink(path, exe, sizeof(exe) - 1);
        if (n < 0) continue;
        exe[n] = '\0';

        struct Event e;
        memset(&e, 0, sizeof(e));
        e.pid = pid;
        e.ppid = ppid;
        strncpy(e.comm, comm, sizeof(e.comm) - 1);
        e.comm[sizeof(e.comm) - 1] = '\0';
        e.event_type = 0;          // synthetic; printer uses event_name, not this
        e.is_process = true;       // /proc lists TGIDs (process leaders)
        e.user_mode_time = utime;
        e.kernel_mode_time = stime;
        e.voluntary_context_switch_count = nvcsw;
        e.involuntary_context_switch_count = nivcsw;
        e.start_time = starttime;
        e.uid = uid_r;
        e.gid = gid_r;
        e.euid = uid_e;
        e.egid = gid_e;
        strncpy(e.filename, exe, sizeof(e.filename) - 1);
        e.filename[sizeof(e.filename) - 1] = '\0';

        print_snapshot_event(out, to_file, args, event_name, &e);
    }

    closedir(d);
}

#endif // KELLECT_LINUX_SNAPSHOT_H
