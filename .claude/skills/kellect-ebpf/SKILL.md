---
name: kellect-ebpf
description: KellectAgent-Linux eBPF build/load/runtime hardening notes from 信创 (Ubuntu Kylin / openKylin) adaptation. Use when building or debugging kellect's BPF programs, generating vmlinux.h on custom kernels, hitting clang "Cannot select: sdiv" / signed-division errors, sizing ringbuf max_entries, or fixing src/trace/all Makefile skeleton dependencies. Activates on kellect eBPF build/load failures, clang BPF-backend errors, vmlinux.h/CO-RE setup, and libbpf 1.0 / bpftool v7 workflows on domestic Linux distros. For general eBPF concepts, use the `ebpf` skill instead.
---

# kellect-ebpf

Project-specific eBPF build/load/runtime lessons for **KellectAgent-Linux**, distilled from `FIXES.md` (信创适配修改清单). Complements the general `ebpf` skill: this one is the kellect-specific gotchas and the verified deploy recipe.

## Scope

- **Use this** for: kellect BPF build failures, `sdiv`/signed-division errors, `vmlinux.h` generation (esp. custom kernels), ringbuf sizing doubts, `all/Makefile` skeleton-dependency link errors, libbpf 1.0 / bpftool v7 behavior on Ubuntu Kylin / openKylin.
- **Use general `ebpf`** for: generic program/map types, verifier triage, bpftrace one-liners, XDP/CO-RE concepts.

## Stack & targets

- libbpf **v1.0.0**, bpftool **v7.0**, clang BPF backend.
- Verified hosts: Ubuntu Kylin 22.04 (kernel 5.15, clang-14) → 33/33; openKylin (kernel 6.1, clang-15.0.7) → 32/32.
- Requirements: `CONFIG_DEBUG_INFO_BTF=y`, `BPF_SYSCALL=y`, `/sys/kernel/btf/vmlinux` present.

## Build recipe (4 steps, verified on both 信创 hosts)

```bash
sudo apt-get install -y clang llvm g++ make libelf-dev zlib1g-dev \
                       linux-tools-common jq python3 curl strace
sudo apt-get install -y linux-tools-$(uname -r) 2>/dev/null \
  || echo "custom kernel: use linux-tools-common bpftool"

cd ~/kellect-linux/src
# 0. vmlinux.h (custom kernel: use /usr/lib/linux-tools/*/bpftool directly)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
# 1. sdiv block
sed -i '111,135s/^/\/\//' src/trace/process/process.bpf.c
# 2. fclose guard
sed -i 's|fclose(output_network);|if (output_network != NULL) fclose(output_network);|g' src/trace/network/network.c
# 3. all/Makefile dependency
sed -i '92a $(OUTPUT)/conf.o: $(OUTPUT)/all.skel.h' src/trace/all/Makefile

cd ..
make clean && make kellect
sudo KELLECT_BIN=./release/kellect bash test/test_kellect.sh 2>&1 | tee /tmp/test.log
```
Expected: **0 failures** (Ubuntu Kylin 33/33, openKylin 32/32).

## 1. vmlinux.h — CO-RE dependency, per-host

- `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` — **required**, upstream repo does not ship it.
- **Custom kernels (openKylin 6.1)**: `/usr/sbin/bpftool` is a version-matching wrapper → `not found for kernel X`. Use the version-agnostic binary directly:
  ```bash
  BPFTOOL=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
  "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
  ```
- Each host generates its own — **do not copy across hosts/kernels**.

## 2. `sdiv` — BPF ISA has NO signed division (compile blocker)

- Site: `src/trace/process/process.bpf.c:111-135` (`handle_exec`): `bpf_get_stack` + `stack_depth/8` integer division.
- Symptom: clang BPF backend → `fatal error: Cannot select: sdiv` / `Unsupport signed division` (sometimes clang **exit code 70**).
- **Root cause = BPF instruction set limit**, NOT a clang bug.
- ⚠️ **clang-14 AND clang-15 both hit it** — this overturns the myth "clang-15 fixed sdiv".
- Fix: avoid signed division in `.bpf.c` — use right-shift (`>>`), unsigned division, or comment the debug block (kellect comments lines 111–135).
- **Rule: never use signed `/` or `%` in BPF programs.**

## 3. ringbuf `max_entries` 512 MB — NOT a problem

- Original process/network/user ringbuf: `512*1024*1024` (512 MB).
- **Verified**: 512 MB compiles, loads, and runs full-functionality on both hosts.
- Why it's fine: `max_entries` is just an integer constant in the `.maps` section — **no memory at compile time**. At load, the kernel allocates; **libbpf 1.0 auto `bump_rlimit_memlock()` → `RLIM_INFINITY`**.
- The old "512 MB → clang exit-70" attribution was **wrong**; exit-70 was the `sdiv`. **Do not reduce ringbuf size.**

## 4. `all/Makefile` skeleton dependency (upstream build bug)

- `conf.c:15` does `#include "all.skel.h"`, but `all/Makefile:92` static rule made `conf.o` depend on `conf.skel.h` (wrong target).
- When `$(wildcard *.bpf.c)` order = **conf before all** → `conf.o` compiles before `all.skel.h` exists → `fatal error: all.skel.h: No such file` → link fails (`test_all`/`test_conf` undefined).
- Ubuntu Kylin masked it (all happened to sort first); openKylin exposed it (conf first).
- Fix: append after line 92: `$(OUTPUT)/conf.o: $(OUTPUT)/all.skel.h`
- **Rule: if a `.c` includes `X.skel.h`, its `.o` must depend on `X.skel.h` — not on its own `<name>.skel.h`.**

## 5. libbpf 1.0 / bpftool v7 notes

- libbpf 1.0 auto-raises memlock rlimit to `RLIM_INFINITY` — no manual `setrlimit`/`ulimit` needed.
- Skeleton flow: `bpftool gen skeleton X.bpf.o > X.skel.h` → userspace `X_bpf__open_and_load()/__attach()`.
- Map definition via `.maps` section with `__uint`/`__type` (BTF-defined maps).

## 6. Runtime gotcha: `fclose(NULL)` in the `-EINTR` path

- `network.c` `test_network`: on signal, `ring_buffer__poll` returns `-EINTR` → `fclose(output_network)`; without `-o`, `output_network == NULL` → **segfault** → clean-exit flush interrupted → buffered events lost → **"0 events" symptom**.
- Fix: `if (output_network != NULL) fclose(output_network);`
- Same latent pattern exists in **5 modules / 10 sites** (`file/process/user/all/conf`) — high event volume masks it; **volume luck, not correctness**. Known, not yet hardened.
- **Rule: never `fclose()` a possibly-NULL `FILE*`; guard all cleanup on signal/error paths.**

## Source

Extracted from `FIXES.md` (信创适配修改清单). Update this skill when a new host/kernel is adapted or a new eBPF build/load pitfall is found.
