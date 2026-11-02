# KellectAgent-Linux — Process & Thread Events

> Part of the [KellectAgent-Linux documentation](../README.md).

### Process & thread (18 event types)

| Id |      Event       |        Key Parameters         |
|:--:|:----------------:|:-----------------------------:|
| 1  |      FORK        |     child_pid, child_comm     |
| 2  |  EXEC / EXECVE / EXECVEAT | filename, old_pid, fd, call stack |
| 3  | CLONE / CLONE3 / VFORK |  flags, stack, tls  |
| 4  | EXIT / EXIT_GROUP |      exit_code, prio         |
| 5  |   PIPE / PIPE2   |     read_fd, write_fd        |
| 6  | KILL / TGKILL / TKILL | pid, signal (sender + target) |
| 7  |     PTRACE       |     request, pid, addr       |
| 8  |      MMAP        | addr, len, prot, flags, fd   |
| 9  |    MPROTECT      |       addr, len, prot        |

## Call Stack Symbolization

Exec events (`EXECVE` / `EXECVEAT`) capture the user-space call stack via `bpf_get_stackid` and resolve it to human-readable symbols with blazesym (including C++ demangling). The stack belongs to the parent's address space (fork inheritance), so symbolization uses the **real parent** captured at event time — short-lived one-liner processes get correctly symbolized stacks too.

