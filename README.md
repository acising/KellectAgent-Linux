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

11 types of file related events are currently supported:

| Id  |     Type of Action      | Number of Parameters |
|:---:|:-----------------------:|:--------------------:|
|  1  |      File Creating      |          4           |
|  2  |      File Deleting      |          3           |
|  3  |  File Renaming/Moving   |          5           |
|  4  |      File Opening       |          4           |
|  5  |    File Mode Setting    |          3           |
|  6  |   File Mode Querying    |          1           |
|  7  | File Directory Changing |          1           |
|  8  | File Directory Creating |          2           |
|  9  | File Directory Deleting |          1           |
| 10  |      File Reading       |          5           |
| 11  |      File Writing       |          5           |

#### 1. File Creating

| Parameter  |                               Description                               |                                                                     Comments                                                                     |
|:----------:|:-----------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------:|
|   `dfd`    |           A file descriptor that refers to an open directory            | If `pathname` is relative and `dfd` is AT_FDCWD, then `pathname` is interpreted relative to the current working directory of the calling process |
| `filename` |                 The filename of the file being created                  |                                                                        -                                                                         |
|  `flags`   |            Additional behavior for opening the file (in HEX)            |                                                                        -                                                                         |
|   `mode`   | Specifies the permissions to use in case a new file is created (in OCT) |                                           Will be ignored if `O_CREAT` or `O_TMPFILE` is not specified                                           |

#### 2. File Deleting

| Parameter  |                              Description                              |      Comments      |
|:----------:|:---------------------------------------------------------------------:|:------------------:|
|   `dfd`    |          A file descriptor that refers to an open directory           | As mentioned above |
| `pathname` | The name of the file being deleted, including the path (if specified) |         -          |
|   `flag`   |               Additional behavior for deleting the file               |         -          | 

#### 3. File Renaming

>Also file moving

| Parameter |                              Description                               | Comments |
|:---------:|:----------------------------------------------------------------------:|:--------:|
| `olddfd`  | The file descriptor of the directory containing the file to be renamed |    -     |
| `oldname` |              The path and name of the file to be renamed               |    -     |
| `newdfd`  |  The file descriptor of the directory where the file will be moved to  |    -     |
| `newname` |                        The new name of the file                        |    -     |
|  `flags`  |               Additional behavior for renaming the file                |    -     | 

#### 4. File Opening

| Parameter  |                               Description                               |                Comments                |
|:----------:|:-----------------------------------------------------------------------:|:--------------------------------------:|
|   `dfd`    |           A file descriptor that refers to an open directory            |           As mentioned above           |
| `filename` |                  The filename of the file being opened                  |                   -                    |
|  `flags`   |            Additional behavior for opening the file (in HEX)            |                   -                    |
|   `mode`   | Specifies the permissions to use in case a new file is created (in OCT) | Will always be `0` when opening a file |

#### 5. File Mode Setting

| Parameter  |                    Description                     |      Comments      |
|:----------:|:--------------------------------------------------:|:------------------:|
|   `dfd`    | A file descriptor that refers to an open directory | As mentioned above |
| `filename` |         The filename of the file being set         |         -          |
|   `mode`   |              The updated `mode` value              |         -          | 

#### 6. File Mode Querying

| Parameter  |              Description               |     Comments      |
|:----------:|:--------------------------------------:|:-----------------:|
| `filename` | The filename of the file being queried |         -         |
|   `mode`   |         The file type and mode         | under development |
|   `uid`    |        The user id of the owner        | under development |
|   `gid`    |       The group id of the owner        | under development |
|  `inode`   |     The `inode` number of the file     | under development | 

#### 7. File Directory Changing

| Parameter  |                        Description                         | Comments |
|:----------:|:----------------------------------------------------------:|:--------:|
| `filename` | The directory after changing the process working directory |    -     | 

#### 8. File Directory Creating

| Parameter  |                             Description                             | Comments |
|:----------:|:-------------------------------------------------------------------:|:--------:|
| `filename` |                     The directory being created                     |    -     |
|   `mode`   | Specifies the permissions to be set for the newly created directory |          |

#### 9. File Directory Deleting

| Parameter  |         Description         | Comments |
|:----------:|:---------------------------:|:--------:|
| `filename` | The directory being deleted |    -     |

#### 10. File Reading

| Parameter  |                        Description                         | Comments |
|:----------:|:----------------------------------------------------------:|:--------:|
|  `count`   | The maximum number of bytes that can be read from the file |    -     |
|  `inode`   |           The `inode` number of the current file           |    -     |
|   `uid`    |              The user id of the file's owner               |    -     |
|   `mode`   |               The file type and permissions                |    -     |
| `filename` |                The name of the current file                |    -     | 

#### 11. File Writing

| Parameter  |                         Description                         | Comments |
|:----------:|:-----------------------------------------------------------:|:--------:|
|  `count`   | The maximum number of bytes that can be write to the file |    -     |
|  `inode`   |           The `inode` number of the current file            |    -     |
|   `uid`    |               The user id of the file's owner               |    -     |
|   `mode`   |                The file type and permissions                |    -     |
| `filename` |                The name of the current file                 |    -     |

### Process & thread

4 types of process/thread related events are currently supported:

| Id  |  Type of Action   | Number of Parameters |
|:---:|:-----------------:|:--------------------:|
|  1  |  Process Forking  |          4           |
|  2  | Process Executing |          3           |
|  3  |  Process Cloning  |          5           |
|  4  |  Process Exiting  |          2           | 

#### 1. Process Forking

|   Parameter   |                           Description                            | Comments |
|:-------------:|:----------------------------------------------------------------:|:--------:|
| `parent_pid`  |                 The `pid` of the current process                 |    -     |
| `parent_comm` | The name of the executable that’s running in the current process |    -     |
|  `child_pid`  |              The `pid` of the forked child process               |    -     |
| `child_comm`  |        The executable's name of the forked child process         |    -     | 

#### 2. Process Executing

| Parameter  |                           Description                            | Comments |
|:----------:|:----------------------------------------------------------------:|:--------:|
|   `pid`    |                 The `pid` of the current process                 |    -     |
| `old_pid`  |         The `pid` of the process before calling `exec()`         |    -     |
| `filename` | The name of the executable that’s running in the current process |    -     | 

#### 3. Process Cloning

|    Parameter    |                                           Description                                           |                                  Comments                                   |
|:---------------:|:-----------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------:|
|  `clone_flags`  |                 Specifies various flags that control the behavior of `clone()`                  |                                      -                                      |
|     `newsp`     |                                 The location of the child stack                                 |                                  A pointer                                  |
|      `tls`      |                  A new TLS (Thread Local Storage) block for the child process                   | This is a pointer. When not using TLS, this parameter will be set to `NULL` |
| `parent_tidptr` |            The location of a variable that will be set to the PID of the new process            |                                  A pointer                                  |
| `child_tidptr`  | The location of a variable that will be set to the PID of the new process’s thread group leader |                                  A pointer                                  | 

#### 4. Process Exiting *(under development)*

|  Parameter   |                          Description                           |     Comments      |
|:------------:|:--------------------------------------------------------------:|:-----------------:|
| `exit_code`  |                    Exit code of the process                    |         -         | 
| `error_code` | Most likely to be the `status` while calling the `exit()` call | under development |
|    `prio`    |       The priority of the process at the time it exited        | under development |

### Network

3 types of process/thread related events are currently supported:

| Id  |      Type of Action       | Number of Parameters |
|:---:|:-------------------------:|:--------------------:|
|  1  |  Connection Establishing  |          5           |
|  2  |  Datagram Socket Sending  |          7           |
|  3  | Datagram Socket Receiving |          7           | 

#### 1. Connection Establishing

| Parameter  |            Description            |                                             Comments                                              |
|:----------:|:---------------------------------:|:-------------------------------------------------------------------------------------------------:|
|    `fd`    | The file descriptor of the socket |                                                 -                                                 |
| `addr_len` |  Length of the address structure  |                                                 -                                                 |
|  `family`  |   Address family of the socket    | IPv4 sockets has value `AF_INET`, which is `2`; IPv6 sockets has value `AF_INET6`, which is `10`; |
|   `port`   |            Port number            |                                                 -                                                 |
|   `addr`   |         IPv4/IPv6 address         |                                                 -                                                 | 

#### 2. Datagram Socket Sending *(under development)*

| Parameter  |                           Description                           |         Comments          |
|:----------:|:---------------------------------------------------------------:|:-------------------------:|
|    `fd`    |                The file descriptor of the socket                |             -             |
|   `len`    |              Maximum length of the data being sent              |             -             |
|  `flags`   |       A bit mask controlling socket-specific I/O features       | When not needed, set to 0 |
| `addr_len` |                 Length of the address structure                 |             -             |
|  `family`  |  Address family of the peer socket which we are communicating   |             -             |
|   `port`   |    Port number of the peer socket which we are communicating    |             -             |
|   `addr`   | IPv4/IPv6 address of the peer socket which we are communicating |             -             |

#### 3. Datagram Socket Receiving *(under development)*

| Parameter  |                                     Description                                      |                                                                                         Comments                                                                                          |
|:----------:|:------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    `fd`    |                          The file descriptor of the socket                           |                                                                                             -                                                                                             |
|   `len`    |                      Maximum length of the data being received                       |                                                                                             -                                                                                             |
|  `flags`   |                 A bit mask controlling socket-specific I/O features                  |                                                                                 When not needed, set to 0                                                                                 |
| `addr_len` | Length of the address structure / number of bytes actually written to this structure | Prior to the call, `addrlen` should be initialized to the size of the structure pointed to by `src_addr`; upon return, it contains the number of bytes actually written to this structure |
|  `family`  |             Address family of the peer socket which we are communicating             |                                                                                             -                                                                                             |
|   `port`   |              Port number of the peer socket which we are communicating               |                                                                                             -                                                                                             |
|   `addr`   |           IPv4/IPv6 address of the peer socket which we are communicating            |                                                                                             -           
                                                                                  |
