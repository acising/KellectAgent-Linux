// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Host identity for multi-host SIEM aggregation (功能对齐差距 #1, 2026-08-23).
// Every JSON line leaving kellect carries "Host-UUID" as its first field
// (injected by output_sink.h's write hook). Without it, events from multiple
// agents merge into an indistinguishable stream at the collector.
//
// Source chain (stable machine identity preferred):
//   /etc/machine-id          - systemd standard, present on both 信创 hosts
//   /var/lib/dbus/machine-id - dbus copy (older systems)
//   /dev/urandom             - per-process fallback (rare; changes across
//                              restarts -- not persisted by design, to keep
//                              the agent side-effect free)
// Output is normalized to 32 lowercase hex chars; empty string if all fail
// (an empty Host-UUID simply disables the injection, never blocks output).

#ifndef KELLECT_LINUX_HOST_UUID_H
#define KELLECT_LINUX_HOST_UUID_H

#include <cstdio>
#include <cstring>
#include <mutex>        /* std::call_once (C++ mode only, kellect-ebpf skill §10) */

static inline const char *get_host_uuid(void)
{
    static char uuid[33];
    static std::once_flag once;
    std::call_once(once, []() {
        const char *sources[] = {"/etc/machine-id", "/var/lib/dbus/machine-id"};
        for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
            FILE *f = fopen(sources[i], "r");
            if (f == NULL) continue;
            char line[64];
            if (fgets(line, sizeof(line), f) != NULL) {
                size_t n = strcspn(line, " \t\r\n");
                if (n == 32) {          /* machine-id is exactly 32 hex chars */
                    memcpy(uuid, line, 32);
                    uuid[32] = '\0';
                    fclose(f);
                    return;             /* lambda-local return: source found */
                }
            }
            fclose(f);
        }
        FILE *f = fopen("/dev/urandom", "rb");
        if (f != NULL) {
            unsigned char raw[16];
            if (fread(raw, 1, sizeof(raw), f) == sizeof(raw)) {
                static const char hex[] = "0123456789abcdef";
                for (int i = 0; i < 16; i++) {
                    uuid[i * 2] = hex[raw[i] >> 4];
                    uuid[i * 2 + 1] = hex[raw[i] & 0xf];
                }
                uuid[32] = '\0';
            }
            fclose(f);
        }
    });
    return uuid;
}

#endif /* KELLECT_LINUX_HOST_UUID_H */
