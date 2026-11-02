# KellectAgent-Linux Manual

> Part of the [KellectAgent-Linux documentation](../README.md). Includes: environment, vmlinux.h preparation, build & run, CLI options, output backends.

## Environment Preparation

Install the necessary dependencies by running the bash commands below (on the build host).

```bash
sudo apt-get install -y clang llvm g++ make libelf-dev zlib1g-dev \
                       linux-tools-common jq python3
```

## Prepare vmlinux.h (required, once per host)

Each BPF source includes `src/vmlinux.h`, generated from the kernel's BTF. Two options:

**Option A — generate locally** (recommended for a new kernel version):

```bash
cd src
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

On openKylin the `/usr/sbin/bpftool` wrapper fails to find the matching version; use the version-agnostic binary directly:

```bash
BPFTOOL=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

**Option B — reuse an existing copy** (safe when the kernel version matches exactly):

```bash
# from another host running the SAME kernel version (check with: uname -r)
scp user@same-kernel-host:~/kellect-linux/src/vmlinux.h src/
```

The rule: same `uname -r` ⇒ the files are byte-identical, copy freely; different kernel versions ⇒ generate locally (compile-time offsets would silently mismatch across kernel versions).

Prerequisites: `CONFIG_DEBUG_INFO_BTF=y` (check `/sys/kernel/btf/vmlinux` exists).

## Build and Run

KellectAgent-Linux currently only supports running as the **root user**.

```bash
cd src
make kellect
sudo ./../release/kellect [options]
```

## Options

```
-e [event_type]    Choose the event domain to trace: all (default), process, file,
                    network, user, image, conf
-f [format]        Output format: text, json (recommended), origin
-o file            Redirect output to a file
-o tcp://host:port Forward events over TCP (auto-reconnect, graceful drain on exit)
-p, --pid <list>    Only emit events from these pids
--exclude-pid <list>  Drop events from these pids
--comm <list>       Only emit events whose comm matches (exact, <=16 chars)
--exclude-comm <list> Drop events whose comm matches
-d                 Debug mode (verbose libbpf output)
```

For example, to trace file events as JSON into a file:

```bash
sudo ./../release/kellect -e file -f json -o /tmp/file.json
```

To forward all events to a remote collector:

```bash
sudo ./../release/kellect -e all -f json -o tcp://192.168.1.10:9999
```

## Output Backends

|   Mode   |                      Behavior                             |
|:--------:|:---------------------------------------------------------:|
| console  | print to stdout (default)                                 |
|   file   | `-o /path/file` — line-buffered, Host-UUID injected       |
|   TCP    | `-o tcp://host:port` — non-blocking queue + dedicated output thread, automatic reconnect (1s), graceful drain on SIGINT so no captured events are lost |

