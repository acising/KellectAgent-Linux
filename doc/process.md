# Details of Process&Thread Event

## 1. Process Forking

|   Parameter   |                           Description                            | Comments |
|:-------------:|:----------------------------------------------------------------:|:--------:|
| `parent_pid`  |                 The `pid` of the current process                 |    -     |
| `parent_comm` | The name of the executable that’s running in the current process |    -     |
|  `child_pid`  |              The `pid` of the forked child process               |    -     |
| `child_comm`  |        The executable's name of the forked child process         |    -     | 

## 2. Process Executing

| Parameter  |                           Description                            | Comments |
|:----------:|:----------------------------------------------------------------:|:--------:|
|   `pid`    |                 The `pid` of the current process                 |    -     |
| `old_pid`  |         The `pid` of the process before calling `exec()`         |    -     |
| `filename` | The name of the executable that’s running in the current process |    -     |
|   `fd`(execveat)    |                 A file descriptor that refers to an open directory                  |    -     |
| `flags`(execveat)  |         Additional behavior for executing process         |    -     |
| `filename` | The name of the executable that’s running in the current process |    -     |  

## 3. Process Cloning

|    Parameter    |                                           Description                                           |                                  Comments                                   |
|:---------------:|:-----------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------:|
|  `clone_flags`  |                 Specifies various flags that control the behavior of `clone()`                  |                                      -                                      |
|     `newsp`     |                                 The location of the child stack                                 |                                  A pointer                                  |
|      `tls`      |                  A new TLS (Thread Local Storage) block for the child process                   | This is a pointer. When not using TLS, this parameter will be set to `NULL` |
| `parent_tidptr` |            The location of a variable that will be set to the PID of the new process            |                                  A pointer                                  |
| `child_tidptr`  | The location of a variable that will be set to the PID of the new process’s thread group leader |                                  A pointer                                  | 

## 4. Process Exiting 

|  Parameter   |                          Description                           |     Comments      |
|:------------:|:--------------------------------------------------------------:|:-----------------:|
| `exit_code`  |                    Exit code of the process                    |         -         | 
|    `prio`    |       The priority of the process at the time it exited        |     -             |
|    `pid`    |       The `pid` of the current process        |     -             |
|    `comm`    |       The commond of the process at the time it exited        |     -             |

## 5. Process Creating Pipe

|  Parameter   |                          Description                           |     Comments      |
|:------------:|:--------------------------------------------------------------:|:-----------------:|
| `fildes`  |                  File descriptors for both read and write ends                  |         -         |
| `flags`  |                    Additional behavior for creating pipe                   |         -         | 

## 6. Process Killing

|  Parameter   |                          Description                           |     Comments      |
|:------------:|:--------------------------------------------------------------:|:-----------------:|
| `pid`  |                    The `pid` of the  process which will be killed                   |         -         | 
| `sig`  |                    a number of signal which will be sent to process               |         -         |
| `tgid`(tgkill)  |                   Thread ID of the main thread in the thread group               |         -         | 

## 7. Process Tracing

|  Parameter   |                          Description                           |     Comments      |
|:------------:|:--------------------------------------------------------------:|:-----------------:|
| `request`  |              a  number indicates which command should be executed                    |         -         | 
| `pid`  |                    The `pid` of the  process which will be traced               |         -         | 
| `addr`  |                    the memory address to be monitored                   |         -         | 
| `data`  |                    data that is read, retrieved, or to be written               |         -         | 

## 8. Process Creating memory-mapped

|  Parameter   |                          Description                           |     Comments      |
|:------------:|:--------------------------------------------------------------:|:-----------------:|
| `addr`  |                    The starting address of the mapping area                   |         -         | 
| `len`  |                    The size of the mapping area               |         -         |
| `prot`  |                   Access permissions for shared memory               |         -         | 
| `flags`  |                    Additional behavior for creating memory-mapped                   |         -         | 
| `fd`  |                    A file descriptor that refers to an open directory               |         -         |
| `off`  |                   The offset of the file pointer during mapping               |         -         | 

## 9. Changing access permissions for process virtual memory areas

|  Parameter   |                          Description                           |     Comments      |
|:------------:|:--------------------------------------------------------------:|:-----------------:|
| `start`  |                     the starting address of the protection  area                   |         -         | 
| `len`  |                   The size of the modified protection attribute area               |         -         |
| `prot`  |                   the memory protection properties               |         -         | 
