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
|  `libbpf`  | v1.0.0  |  [GitHub link](https://github.com/libbpf/libbpf)  |

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

## Output Format

`Kellect` currently supports *three* major event types:

- file related events
- process and thread related events
- network related events

We output event records in JSON format, or output them directly to the console. Each `BaseEvent` has two parts of properties: *common* properties and *private* properties.

The *common properties* we could infer from any triggered events is listed below:

|   Parameter    |                                                         Description                                                          | Comments |
|:--------------:|:----------------------------------------------------------------------------------------------------------------------------:|:--------:|
|  `timestamp`   |                                               Current timestamp in microsecond                                               |    -     |
|  `event_type`  |                                                The type of the current event                                                 |    -     |
|     `comm`     |                  The name of the executable that’s running in the process which triggered the current event                  |    -     |
|     `pid`      |                                                The identifier of the process                                                 |    -     |
|     `ppid`     | `TGID`, it means that the current event is triggered by a process when equals to `pid`, otherwise it's triggered by a thread |    -     |
| `process_type` |                                                To identify process and thread                                                |    -     | 

The *private properties* we could infer from supported events is listed below:

### File

16 types of file related events are currently supported:

| Id  |     Type of Action      | Number of Parameters |
|:---:|:-----------------------:|:--------------------:|
|  1  |      File Creating      |          4           |
|  2  |      File Deleting      |          3           |
|  3  |  File Renaming/Moving   |          5           |
|  4  |      File Opening       |          4           |
|  5  |    File Mode Setting    |          3           |
|  6  |   File Mode Querying    |          4           |
|  7  | File Directory Changing |          2           |
|  8  | File Directory Creating |          2           |
|  9  | File Directory Deleting |          1           |
| 10  |      File Reading       |          5           |
| 11  |      File Writing       |          5           |
| 12  |      File Descriptor Copying       |          2           |
| 13  |      File Closing       |          1           |
| 14  |      File Truncating       |          3           |
| 15  |      File Creating Link       |          5           |
| 16  |      File Create Symbolic Link       |          3           |

details of each event can be found in [here](doc/file.md)

### Process & thread

9 types of process/thread related events are currently supported:

| Id  |  Type of Action   | Number of Parameters |
|:---:|:-----------------:|:--------------------:|
|  1  |  Process Forking  |          4           |
|  2  | Process Executing |          6           |
|  3  |  Process Cloning  |          5           |
|  4  |  Process Exiting  |          4           | 
|  5  |  Process Creating Pipe  |          2           |
|  6  |  Process Killing  |          3           |
|  7  |  Process Tracing  |          4           |
|  8  |  Process Creating memory-mapped  |          6           |
|  9  |  Changing access permissions for process virtual memory areas  |          3           |

details of each event can be found in [here](doc/process.md)

### Network

7 types of process/thread related events are currently supported:

| Id  |      Type of Action       | Number of Parameters |
|:---:|:-------------------------:|:--------------------:|
|  1  |  Connection Establishing  |          5           |
|  2  |  Datagram Socket Sending  |          7           |
|  3  | Datagram Socket Receiving |          7           | 
|  4  | Connection Accepting |          6           |
|  5  | Socket Binding |          5           |
|  6  | Getting The Name Of The Connected Peer Socket |          5           |
|  7  | Establish a Pair Of Connected Sockets |          4           |

details of each event can be found in [here](doc/network.md)

### User

6 types of process/thread related events are currently supported:

| Id  |      Type of Action       | Number of Parameters |
|:---:|:-------------------------:|:--------------------:|
|  1  |  Gid Setting  |          1           |
|  2  |  Real&Effective Gid  Setting  |          2           |
|  3  | Real&Effective Gid and Savedgid Setting |          3           | 
|  4  | Uid Setting |          1           |
|  5  | Real&Effective Uid  Setting |          2           |
|  6  | Real&Effective uid and Saveduid Setting |          3           |

details of each event can be found in [here](doc/user.md)
