// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// v1 userspace event filter: include (union) + exclude (drop-on-match).
// Header-only inline so it can be dropped into every loader without touching
// the build system. Decoupled from the per-domain event structs: callers pass
// only the envelope fields (pid + comm) and the parsed Args.
//
#ifndef KELLECT_LINUX_FILTER_H
#define KELLECT_LINUX_FILTER_H

#include <vector>
#include <string>
#include <string.h>
#include "arg_parser.h"

// Returns true when the event should be DROPPED.
static inline bool event_filtered_out(int pid, const char *comm, const struct Args *args)
{
    if (!args) {
        return false;
    }

    // include (union): if any include list is set, the event must match at
    // least one include rule (a listed pid OR a listed comm); otherwise drop.
    bool has_include = !args->include_pids.empty() || !args->include_comms.empty();
    if (has_include) {
        bool in_pid = false;
        bool in_comm = false;
        for (int p : args->include_pids) {
            if (p == pid) { in_pid = true; break; }
        }
        if (comm) {
            for (const auto &c : args->include_comms) {
                if (strcmp(c.c_str(), comm) == 0) { in_comm = true; break; }
            }
        }
        if (!in_pid && !in_comm) {
            return true;
        }
    }

    // exclude (drop on match)
    for (int p : args->exclude_pids) {
        if (p == pid) { return true; }
    }
    if (comm) {
        for (const auto &c : args->exclude_comms) {
            if (strcmp(c.c_str(), comm) == 0) { return true; }
        }
    }

    return false;
}

#endif // KELLECT_LINUX_FILTER_H
