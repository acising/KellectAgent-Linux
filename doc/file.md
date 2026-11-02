# KellectAgent-Linux — File Events

> Part of the [KellectAgent-Linux documentation](../README.md).

### File (28 event types)

| Id |       Event        |        Key Parameters        |
|:--:|:------------------:|:----------------------------:|
| 1  |     OPEN_FILE      |    filename, flags, mode     |
| 2  |     READ_FILE     |    filename, count, pos      |
| 3  |     WRITE_FILE    |    filename, count, pos      |
| 4  |       DELETE      |        filename, flags        |
| 5  |    RENAME / RENAMEAT / RENAMEAT2 |  oldname, newname  |
| 6  |  CHMOD / FCHMOD / CHANGE_MODE / GET_MODE | filename, mode |
| 7  |   MAKE_DIR / MKDIRAT / REMOVE_DIR  |    dirname, mode     |
| 8  |     CHANGE_DIR    |        filename, fd         |
| 9  |  LINK / LINKAT / SYMLINK / SYMLINKAT | oldpath, newpath |
| 10 | CLOSE / DUP / DUP2 |        fd, newfd          |
| 11 | TRUNCATE / FTRUNCATE |    filename, length      |
| 12 | PREAD64 / PREADV / PWRITE64 / PWRITEV | filename, count, offset |

