# **KellectAgent-Linux** : a **K**ernel-based Efficient and **L**oss**l**ess Event Log Coll**ec**tor for Linux

![](http://121.40.168.60/kellect/kellect.jpeg)

## Introduction

### Kellect

**Kellect** (a **K**ernel-based efficient and **L**oss**l**ess event log coll**ec**tor) is a system framework for kernel-level event log processing, including the stages of acquisition, cleaning, fusion, storage and analysis. **KELLCT** is divided into **KellectAgent** and **KellectService** according to different functions.

### KellectAgent-Linux

With the help of **eBPF** (**e**xtended **B**erkeley **P**acket **F**ilter), KellectAgent-Linux implements kernel-level event tracing on the Linux system.

eBPF is a highly efficient and flexible virtual machine that allows for safe and secure programmability of the Linux kernel. Now, with its help, KellectAgent-Linux is enabled to perform powerful kernel-level event tracing, allowing for detailed analysis and troubleshooting of system behavior. With eBPF, KellectAgent-Linux can capture and analyze events across a wide range of system components, including file operations, processes, and networking.

## Implementation Details

KellectAgent-Linux uses a number of third-party libraries, which are listed below.

|   Module   | Version |                        URL                        |
|:----------:|:-------:|:-------------------------------------------------:|
| `bpftool`  |  v7.0   | [GitHub link](https://github.com/libbpf/bpftool)  |
|  `libbpf`  | v1.0.0  |  [GitHub link](hKellect-Linuxttps://github.com/libbpf/libbpf)  |

The system and kernel supported currently are listed below.

| System | System Version |   Kernel Version    |
|:------:|:--------------:|:-------------------:|
| Ubuntu |  `20.04 LTS`   | `5.15.0-50-generic` | 

The development of KellectAgent-Linux is carried out on CLion and VSCode. The software and versions used for development are listed below.

|  Tool  | Version |
|:------:|:-------:|
| CLion  | 2022.03 | 
| VSCode | 1.77.0  |

The directory of KellectAgent-Linux is shown below.

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

## KellectAgent-Linux Manual

### Environment Preparation

Install the necessary dependencies by running the bash commands below.

```bash
sudo apt-get install libelf-dev
sudo apt-get install clang
sudo apt-get install llvm
sudo apt-get install libc6-dev-i386
```

### How to Use

KellectAgent-Linux currently only supports running as the **root user**.

```bash
cd src
make kellect
sudo ./../release/kellect [arguments]
```

For example, if you want to trace file events, then using the following command would be useful:

```bash
sudo ./../release/kellect -e file
```
