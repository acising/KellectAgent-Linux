# **Kellect-Linux** : a **K**ernel-based Efficient and **L**oss**l**ess Event Log Coll**ec**tor for Linux

![](http://121.40.168.60/kellect/kellect.jpeg)

## Introduction

### kellect

**Kellect** means a **K**ernel-based efficient and **L**oss**l**ess event log coll**ec**tor which is a systematic framework for the full processing on kernel level logs, including collection, cleanup, confusion, storage, and analysis.

As a firstborn version, [Kellect](https://github.com/acising/kellect/) is a multi-threaded Windows kernel log collector based on ETW(BaseEvent Tracing for Windows), developed in C++ language with high-efficient performance. kellect can track kernel-level information of Windows system, such as FileIO, Process, Thread, ImageLoad, Registry, and so on.

### Kellect-Linux

With the help of **eBPF** (**e**xtended **B**erkeley **P**acket **F**ilter), Kellect-Linux implements kernel-level event tracing on the Linux system.

eBPF is a highly efficient and flexible virtual machine that allows for safe and secure programmability of the Linux kernel. Now, with its help, Kellect-Linux is enabled to perform powerful kernel-level event tracing, allowing for detailed analysis and troubleshooting of system behavior. With eBPF, Kellect-Linux can capture and analyze events across a wide range of system components, including file operations, processes, and networking.

## Implementation Details

Kellect-Linux uses a number of third-party libraries, which are listed below.

|   Module   | Version |                        URL                        |
|:----------:|:-------:|:-------------------------------------------------:|
| `bpftool`  |    /    | [GitHub link](https://github.com/libbpf/bpftool)  |
|  `libbpf`  |    /    |  [GitHub link](https://github.com/libbpf/libbpf)  |
| `blazesym` |    /    | [GitHub link](https://github.com/libbpf/blazesym) | 

The system and kernel supported currently are listed below.

| System | System Version |   Kernel Version    |
|:------:|:--------------:|:-------------------:|
| Ubuntu |  `20.04 LTS`   | `5.15.0-50-generic` | 

The development of Kellect-Linux is carried out on CLion and VSCode. The software and versions used for development are listed below.

|  Tool  | Version |
|:------:|:-------:|
| CLion  | 2022.03 | 
| VSCode | 1.77.0  |

The directory of Kellect-Linux is shown below.

|   Directory    |     Purpose      |
|:--------------:|:----------------:|
|   `release`    | Executable files |
|  `src/basic`   |   Common files   |
| `src/blazesym` | `blazesym` tool  |
| `src/bpftool`  |  `bpftool` tool  |
| `src/include`  |   Header files   |
|  `src/libbpf`  |  `libbpf` tool   |
|  `src/tools`   |      Tools       |
|  `src/trace`   |   Source files   | 

## Kellect-Linux Manual

### Environment Preparation

Install the necessary dependencies by running the bash commands below.

```bash
sudo apt-get install libelf-dev
sudo apt-get install clang
sudo apt-get install llvm
sudo apt-get install libc6-dev-i386
```

### How to Use

Kellect-Linux currently only supports running as the **root user**.

```bash
cd src
make kellect
sudo ./../release/kellect [arguments]
```

For example, if you want to trace file events, then using the following command would be useful:

```bash
sudo ./../release/kellect -e file
```
