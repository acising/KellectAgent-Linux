# **KellectAgent-Linux** : a **K**ernel-based Efficient and **L**oss**l**ess Event Log Coll**ec**tor for Linux

## Introduction

### Kellect

**Kellect** (a **K**ernel-based efficient and **L**oss**l**ess event log coll**ec**tor) is a system framework for kernel-level event log processing, including the stages of acquisition, cleaning, fusion, storage and analysis. **KELLECT** is divided into **KellectAgent** and **KellectService** according to different functions.

### KellectAgent-Linux

With the help of **eBPF** (**e**xtended **B**erkeley **P**acket **F**ilter), KellectAgent-Linux implements kernel-level event tracing on the Linux system, covering file, process/thread, network, user-credential, and image (executable memory) event domains, with call-stack symbolization and reliable event delivery (local file or TCP forwarding with auto-reconnect).

## Implementation Details

KellectAgent-Linux uses a number of third-party libraries, which are listed below.

|    Module    | Version |                                  URL                                  | Purpose                          |
|:------------:|:-------:|:---------------------------------------------------------------------:|:---------------------------------|
|  `bpftool`   |  v7.0   |        [GitHub link](https://github.com/libbpf/bpftool)              | skeleton generation, BTF dump    |
|   `libbpf`   | v1.0.0  |        [GitHub link](https://github.com/libbpf/libbpf)               | BPF loader (CO-RE)               |
|  `blazesym`  | prebuilt | [GitHub link](https://github.com/libbpf/blazesym)                   | call-stack symbolization (statically linked) |

`libbpf` and `bpftool` are vendored under `src/` and built from source; the blazesym C library ships prebuilt under `src/include/`.

The system and kernel supported currently are listed below.

|       System        | System Version |     Kernel Version     |
|:-------------------:|:--------------:|:----------------------:|
| Ubuntu Kylin  |     22.04      |   5.15.0-25-generic    |
|      openKylin      |       -        | 6.1.0-4-generic (custom `#5ok1-KYLINOS`) |

The directory of KellectAgent-Linux is shown below.

|   Directory    |               Purpose               |
|:--------------:|:-----------------------------------:|
|   `release`    |   Executable files (on the build host) |
|  `src/basic`   |   Argument parsing and common utils  |
| `src/bpftool`  |           `bpftool` tool             |
| `src/include`  | Header files, blazesym prebuilt libs |
|  `src/libbpf`  |           `libbpf` library           |
|  `src/trace`   |   Per-domain loader and BPF sources  |
|     `doc`      |          Documentation               |

## Quick Start

```bash
# 1. install dependencies
sudo apt-get install -y clang llvm g++ make libelf-dev zlib1g-dev linux-tools-common

# 2. prepare vmlinux.h (generate locally or reuse from a same-kernel host — see doc/manual.md)
cd src && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 3. build & run as root
make kellect
sudo ./../release/kellect -e file -f json -o /tmp/file.json
```

Full CLI options, vmlinux.h reuse rules, and the TCP forwarding backend are documented in [doc/manual.md](doc/manual.md).

## Documentation

KellectAgent-Linux supports **six** event domains. Every event is a single JSON line carrying the host identity (`Host-UUID`); process-domain events carry the parent identity, and exec events carry the symbolized user call stack.

|                                      Domain                                      | Event Types |
|:--------------------------------------------------------------------------------:|:-----------:|
|            [File](doc/file.md) — open/read/write/delete/rename/link/...           |     28      |
| [Process & Thread](doc/process.md) — fork/exec/clone/exit/kill/ptrace + call stack |     18      |
|      [Network](doc/network.md) — connect/accept/send/recv + TCP lifecycle (disconnect, retransmit, failure)      |  12 + 6   |
|          [User](doc/user.md) — setuid/setgid family (privilege-change auditing)   |      7      |
|        [Image](doc/image.md) — load/mprotect injection/unload/kernel modules      |      5      |
|               [Manual](doc/manual.md) — build, options, output backends           |      -      |
