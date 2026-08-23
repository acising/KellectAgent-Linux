// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// #9 Output backend subsystem: SPSC lock-free queue + output thread + TCP
// socket with auto-reconnect.
//
// Architecture (validated by spike/output_backend_spike.c, 2026-08-14):
//
//   BPF ringbuf -> handle_event -> fprintf(output_xxx) -> fopencookie write hook
//                                                              | non-blocking
//                                                   SPSC queue (memcpy, O(1))
//                                                              |
//                                                   output thread (consumer)
//                                                              | blocking OK
//                                                   TCP socket w/ reconnect
//
// Why fopencookie is safe here (production-audit reversal):
//   The audit rejected fopencookie when its write hook does blocking socket
//   I/O. Here the write hook only does queue_push (non-blocking memcpy). All
//   I/O risk (partial write, reconnect, blocking) is isolated in the output
//   thread. The BPF poll loop never blocks, never silently drops on collector
//   failure -- the queue absorbs bursts and the thread reconnects.
//
// Why SPSC lock-free (CP.100 says "don't use lock-free unless you have to"):
//   Exactly one producer (the ring_buffer__poll callback, single-threaded by
//   libbpf) and exactly one consumer (our output thread). This is the textbook
//   SPSC case where atomics are correct and simpler than a mutex (no lock
//   contention on the hot BPF poll path).
//
// C++ compatibility note: kellect's .c files are compiled with g++ (CXX),
// so this header uses std::atomic (C++11) instead of C11 _Atomic. The
// <atomic> header provides std::atomic_load/store and std::memory_order_*.

#ifndef KELLECT_LINUX_OUTPUT_SINK_H
#define KELLECT_LINUX_OUTPUT_SINK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* fopencookie, MSG_NOSIGNAL */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <atomic>       /* C++11 std::atomic (not C11 _Atomic) */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "arg_parser.h"  /* struct Args (needed by create_output_sink) */
#include "host_uuid.h"   /* host identity injected into every JSON line */

/* ES.45: named constants, not magic numbers */
#define OUTPUT_QUEUE_CAPACITY  4096   /* events buffered during collector outage */
#define OUTPUT_EVENT_MAX_LEN   640    /* max formatted event size; was 512, raised for
                                       * Host-UUID prefix (+48B) and long UserStack
                                       * JSON rows (功能对齐 #1, 2026-08-23) */
#define OUTPUT_RECONNECT_DELAY 1      /* seconds between reconnect attempts */
#define OUTPUT_IDLE_POLL_US    1000   /* 1ms idle wait when queue empty */

/* ============================================================
 * SPSC lock-free bounded queue (ring buffer)
 * ============================================================ */

typedef struct {
    char data[OUTPUT_EVENT_MAX_LEN];
    int  len;
} output_queue_entry_t;

typedef struct {
    output_queue_entry_t entries[OUTPUT_QUEUE_CAPACITY];
    std::atomic<uint32_t> head;            /* producer writes */
    std::atomic<uint32_t> tail;            /* consumer writes */
    std::atomic<uint64_t> dropped;         /* drop counter (observability) */
} output_queue_t;

static inline void output_queue_init(output_queue_t *q)
{
    std::atomic_store(&q->head, (uint32_t)0);
    std::atomic_store(&q->tail, (uint32_t)0);
    std::atomic_store(&q->dropped, (uint64_t)0);
}

/* Producer: non-blocking push. Returns true on success, false if full. */
static inline bool output_queue_push(output_queue_t *q, const char *data, int len)
{
    if (len > OUTPUT_EVENT_MAX_LEN) {
        len = OUTPUT_EVENT_MAX_LEN;
    }
    uint32_t head = std::atomic_load_explicit(&q->head, std::memory_order_relaxed);
    uint32_t next = (head + 1) % OUTPUT_QUEUE_CAPACITY;
    uint32_t tail = std::atomic_load_explicit(&q->tail, std::memory_order_acquire);

    if (next == tail) {
        /* Queue full -- explicit drop, never block the BPF poll thread */
        std::atomic_fetch_add_explicit(&q->dropped, (uint64_t)1, std::memory_order_relaxed);
        return false;
    }

    memcpy(q->entries[head].data, data, len);
    q->entries[head].len = len;
    std::atomic_store_explicit(&q->head, next, std::memory_order_release);
    return true;
}

/* Consumer: non-blocking pop. Returns true on success, false if empty. */
static inline bool output_queue_pop(output_queue_t *q, char *out_data, int *out_len)
{
    uint32_t tail = std::atomic_load_explicit(&q->tail, std::memory_order_relaxed);
    uint32_t head = std::atomic_load_explicit(&q->head, std::memory_order_acquire);

    if (tail == head) {
        return false;  /* empty */
    }

    *out_len = q->entries[tail].len;
    memcpy(out_data, q->entries[tail].data, *out_len);
    std::atomic_store_explicit(&q->tail, (tail + 1) % OUTPUT_QUEUE_CAPACITY, std::memory_order_release);
    return true;
}

/* ============================================================
 * TCP backend: connect / send_all (partial-write safe)
 * ============================================================ */

static inline int output_tcp_connect(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* Complete send (handles partial write). Returns 0 on success, -1 on failure. */
static inline int output_tcp_send_all(int fd, const char *data, int len)
{
    int sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;  /* disconnected, caller will reconnect */
        }
        if (n == 0) {
            return -1;
        }
        sent += (int)n;
    }
    return 0;
}

/* ============================================================
 * Cookie state (passed to fopencookie, shared between hooks + thread)
 * ============================================================ */

typedef struct {
    output_queue_t  queue;
    pthread_t       thread;
    std::atomic<bool> exiting;
    std::atomic<uint64_t> produced;
    std::atomic<uint64_t> sent;
    char            line_buf[OUTPUT_EVENT_MAX_LEN];  /* accumulate until \n */
    int             line_len;
    char            host[256];
    int             port;
} output_cookie_t;

/* ============================================================
 * Output thread (consumer): drain queue -> TCP socket
 * ============================================================ */

static inline void *output_thread_fn(void *arg)
{
    output_cookie_t *oc = (output_cookie_t *)arg;
    int fd = -1;  /* lazy connect inside the loop */
    char buf[OUTPUT_EVENT_MAX_LEN];
    int  len;

    /* Graceful-shutdown semantics (drain-then-join): once `exiting` is set,
     * keep sending while the queue still has entries AND the connection is
     * alive — an audit collector must not discard already-captured events on
     * a clean SIGINT. Bounded: if disconnected during shutdown, stop instead
     * of reconnecting (unresolved entries stay visible in produced - sent). */
    while (true) {
        const bool exiting = std::atomic_load(&oc->exiting);

        if (fd < 0) {
            if (exiting) {
                break;  /* shutdown with no connection: stop draining */
            }
            fd = output_tcp_connect(oc->host, oc->port);
            if (fd < 0) {
                sleep(OUTPUT_RECONNECT_DELAY);
                continue;
            }
        }

        if (output_queue_pop(&oc->queue, buf, &len)) {
            if (output_tcp_send_all(fd, buf, len) < 0) {
                close(fd);
                fd = -1;
                if (exiting) {
                    break;  /* don't reconnect during shutdown */
                }
            } else {
                std::atomic_fetch_add(&oc->sent, (uint64_t)1);
            }
        } else if (exiting) {
            break;  /* queue fully drained */
        } else {
            usleep(OUTPUT_IDLE_POLL_US);
        }
    }

    if (fd >= 0) {
        close(fd);
    }
    return NULL;
}

/* ============================================================
 * fopencookie write hook: accumulate until \n, then queue_push
 *
 * fprintf may deliver a single event in multiple write calls (large JSON).
 * We buffer fragments in cookie->line_buf until we see a newline, then push
 * the complete line as one queue entry. This matches the collector's
 * line-oriented protocol.
 * ============================================================ */

/* Shared line-finalize: inject Host-UUID as the first field of JSON lines
 * (leading '{'). One helper serves both the TCP hook (queue path) and the
 * file hook (direct write path). Text lines pass through unchanged; lines
 * that would overflow the slot are left as-is (line integrity beats the
 * label). Returns the (possibly extended) line length. */
static inline int output_inject_host_uuid(char *line_buf, int line_len)
{
    if (line_len > 0 && line_buf[0] == '{') {
        const char *hu = get_host_uuid();
        if (hu[0] != '\0') {
            char inject[56];
            int il = snprintf(inject, sizeof(inject), "{\"Host-UUID\":\"%s\",", hu);
            if (il > 0 && (size_t)line_len - 1 + (size_t)il <= OUTPUT_EVENT_MAX_LEN - 1) {
                /* strip the leading '{', shift the body right, splice the
                 * prefix -- memmove handles the overlap */
                memmove(line_buf + il, line_buf + 1, (size_t)line_len - 1);
                memcpy(line_buf, inject, (size_t)il);
                line_len = (int)((size_t)line_len - 1 + (size_t)il);
                line_buf[line_len] = '\0';
            }
        }
    }
    return line_len;
}

static inline ssize_t output_cookie_write(void *cookie, const char *buf, size_t size)
{
    output_cookie_t *oc = (output_cookie_t *)cookie;

    for (size_t i = 0; i < size; i++) {
        if (oc->line_len < OUTPUT_EVENT_MAX_LEN - 1) {
            oc->line_buf[oc->line_len++] = buf[i];
        }

        if (buf[i] == '\n' || oc->line_len >= OUTPUT_EVENT_MAX_LEN - 1) {
            /* Complete line (or buffer full) -- push to queue */
            if (oc->line_len < OUTPUT_EVENT_MAX_LEN) {
                oc->line_buf[oc->line_len] = '\0';
            }
            oc->line_len = output_inject_host_uuid(oc->line_buf, oc->line_len);
            if (output_queue_push(&oc->queue, oc->line_buf, oc->line_len)) {
                std::atomic_fetch_add(&oc->produced, (uint64_t)1);
            }
            /* If push fails (queue full), output_queue_push incremented dropped. */
            oc->line_len = 0;
        }
    }

    return (ssize_t)size;  /* always report full consumption (non-blocking) */
}

static inline int output_cookie_close(void *cookie)
{
    output_cookie_t *oc = (output_cookie_t *)cookie;

    /* Signal thread to exit and wait for it (P.8: no resource leak).
     * The thread runs drain-then-join: it keeps sending queued events until
     * the queue empties or the connection breaks (see output_thread_fn), so
     * join may block briefly while the backlog flushes. fclose already
     * flushed the stdio buffer (write hook → queue) before this close hook
     * runs, so all produced events are in the queue by the time we join. */
    std::atomic_store(&oc->exiting, true);
    pthread_join(oc->thread, NULL);

    /* Log drop statistics to stderr (diagnostic, not event stream) */
    uint64_t dropped  = std::atomic_load(&oc->queue.dropped);
    uint64_t produced = std::atomic_load(&oc->produced);
    uint64_t sent     = std::atomic_load(&oc->sent);
    if (dropped > 0 || produced > 0) {
        fprintf(stderr, "[output_sink] produced=%llu sent=%llu dropped=%llu\n",
                (unsigned long long)produced,
                (unsigned long long)sent,
                (unsigned long long)dropped);
    }

    free(oc);
    return 0;
}

/* ============================================================
 * Public API: create_output_sink / close_output_sink
 *
 * Factory: TCP mode -> fopencookie FILE* + output thread (queue path).
 *          File mode -> fopencookie wrapper over the plain fopen'd file
 *          (direct-write path, no queue/thread) so Host-UUID injection
 *          covers BOTH output paths (host-verified gap fix, 2026-08-23).
 * ============================================================ */

/* Lightweight file cookie: inject, then write straight to the underlying
 * FILE* (its own stdio buffering applies). No queue, no thread, no stats. */
typedef struct {
    FILE *fp;                                  /* underlying file */
    char  line_buf[OUTPUT_EVENT_MAX_LEN];
    int   line_len;
} file_cookie_t;

static inline ssize_t file_cookie_write(void *cookie, const char *buf, size_t size)
{
    file_cookie_t *fc = (file_cookie_t *)cookie;

    for (size_t i = 0; i < size; i++) {
        if (fc->line_len < OUTPUT_EVENT_MAX_LEN - 1) {
            fc->line_buf[fc->line_len++] = buf[i];
        }
        if (buf[i] == '\n' || fc->line_len >= OUTPUT_EVENT_MAX_LEN - 1) {
            fc->line_len = output_inject_host_uuid(fc->line_buf, fc->line_len);
            fwrite(fc->line_buf, 1, (size_t)fc->line_len, fc->fp);
            fc->line_len = 0;
        }
    }

    return (ssize_t)size;
}

static inline int file_cookie_close(void *cookie)
{
    file_cookie_t *fc = (file_cookie_t *)cookie;
    fflush(fc->fp);
    fclose(fc->fp);   /* the underlying file */
    free(fc);
    return 0;
}

static inline FILE *create_output_sink(const struct Args *args)
{
    if (args->if_output_to_tcp) {
        /* TCP backend: allocate cookie, init queue, spawn thread */
        output_cookie_t *oc = (output_cookie_t *)calloc(1, sizeof(output_cookie_t));
        if (!oc) {
            return NULL;
        }

        output_queue_init(&oc->queue);
        std::atomic_store(&oc->exiting, false);
        std::atomic_store(&oc->produced, (uint64_t)0);
        std::atomic_store(&oc->sent, (uint64_t)0);
        oc->line_len = 0;
        strncpy(oc->host, args->tcp_host.c_str(), sizeof(oc->host) - 1);
        oc->host[sizeof(oc->host) - 1] = '\0';
        oc->port = args->tcp_port;

        /* Spawn output thread (lazy connect inside thread) */
        if (pthread_create(&oc->thread, NULL, output_thread_fn, oc) != 0) {
            free(oc);
            return NULL;
        }

        /* Create fopencookie FILE* with our write + close hooks */
        cookie_io_functions_t io_funcs;
        memset(&io_funcs, 0, sizeof(io_funcs));
        io_funcs.write = output_cookie_write;
        io_funcs.close = output_cookie_close;

        FILE *fp = fopencookie(oc, "w", io_funcs);
        if (!fp) {
            std::atomic_store(&oc->exiting, true);
            pthread_join(oc->thread, NULL);
            free(oc);
            return NULL;
        }

        /* Line-buffered: flush write hook on every \n (matches line_buf logic) */
        setvbuf(fp, NULL, _IOLBF, 0);

        return fp;
    }

    /* File mode: wrap the plain fopen'd file in a fopencookie layer so the
     * shared Host-UUID injection applies (same behavior as the TCP path). */
    if (args->output_file.empty()) {
        return NULL;
    }
    FILE *underlying = fopen(args->output_file.c_str(), "w");
    if (!underlying) {
        return NULL;
    }
    file_cookie_t *fc = (file_cookie_t *)calloc(1, sizeof(file_cookie_t));
    if (!fc) {
        fclose(underlying);
        return NULL;
    }
    fc->fp = underlying;
    fc->line_len = 0;

    cookie_io_functions_t file_io;
    memset(&file_io, 0, sizeof(file_io));
    file_io.write = file_cookie_write;
    file_io.close = file_cookie_close;
    FILE *wfp = fopencookie(fc, "w", file_io);
    if (!wfp) {
        fclose(underlying);
        free(fc);
        return NULL;
    }
    setvbuf(wfp, NULL, _IOLBF, 0);   /* line-buffered, same as TCP path */
    return wfp;
}

/* close_output_sink: works for both TCP and file modes -- both return a
 * fopencookie FILE*, so plain fclose triggers the matching close hook
 * (TCP: drain-then-join; file: fflush + fclose underlying). */
static inline void close_output_sink(FILE *fp)
{
    if (fp != NULL) {
        fclose(fp);  /* for fopencookie, this triggers output_cookie_close */
    }
}

#endif /* KELLECT_LINUX_OUTPUT_SINK_H */
