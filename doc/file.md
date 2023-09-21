# Details of File Event

## 1. File Creating

| Parameter  |                               Description                               |                                                                     Comments                                                                     |
|:----------:|:-----------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------:|
|   `dfd`    |           A file descriptor that refers to an open directory            | If `pathname` is relative and `dfd` is AT_FDCWD, then `pathname` is interpreted relative to the current working directory of the calling process |
| `filename` |                 The filename of the file being created                  |                                                                        -                                                                         |
|  `flags`   |            Additional behavior for opening the file (in HEX)            |                                                                        -                                                                         |
|   `mode`   | Specifies the permissions to use in case a new file is created (in OCT) |                                           Will be ignored if `O_CREAT` or `O_TMPFILE` is not specified                                           |

## 2. File Deleting

| Parameter  |                              Description                              |      Comments      |
|:----------:|:---------------------------------------------------------------------:|:------------------:|
|   `dfd`(unlinkat)    |          A file descriptor that refers to an open directory           | As mentioned above |
| `pathname` | The name of the file being deleted, including the path (if specified) |         -          |
|   `flag`(unlinkat)   |               Additional behavior for deleting the file               |         -          | 

## 3. File Renaming

>Also file moving

| Parameter |                              Description                               | Comments |
|:---------:|:----------------------------------------------------------------------:|:--------:|
| `olddfd`(renameat,renameat2)| The file descriptor of the directory containing the file to be renamed |    -     |
| `oldname` |              The path and name of the file to be renamed               |    -     |
| `newdfd`(renameat,renameat2)  |  The file descriptor of the directory where the file will be moved to  |    -     |
| `newname` |                        The new name of the file                        |    -     |
|  `flags`(renameat2)  |               Additional behavior for renaming the file                |    -     | 

## 4. File Opening

| Parameter  |                               Description                               |                Comments                |
|:----------:|:-----------------------------------------------------------------------:|:--------------------------------------:|
|   `dfd`    |           A file descriptor that refers to an open directory            |           As mentioned above           |
| `filename` |                  The filename of the file being opened                  |                   -                    |
|  `flags`   |            Additional behavior for opening the file (in HEX)            |                   -                    |
|   `mode`   | Specifies the permissions to use in case a new file is created (in OCT) | Will always be `0` when opening a file |

## 5. File Mode Setting

| Parameter                 |                    Description                     |      Comments      |
|:-------------------------:|:--------------------------------------------------:|:------------------:|
| `dfd`(fchmod,fchmodat)    | A file descriptor that refers to an open directory | As mentioned above |
| `filename`(chmod,fchmodat)|         The filename of the file being set         |         -          |
|          `mode`           |              The updated `mode` value              |         -          | 

## 6. File Mode Querying

| Parameter  |              Description               |     Comments      |
|:----------:|:--------------------------------------:|:-----------------:|
| `filename` | The filename of the file being queried |         -         |
|   `mode`   |         The file type and mode         |         -         |
|   `uid`    |        The user id of the owner        |         -         |
|   `gid`    |       The group id of the owner        |         -         |
|  `inode`   |     The `inode` number of the file     | under development | 

## 7. File Directory Changing

| Parameter         |                        Description                         | Comments |
|:-----------------:|:----------------------------------------------------------:|:--------:|
| `filename`(chdir) | The directory after changing the process working directory |    -     |
|   `dfd`(fchdir)   |      A file descriptor that refers to an open directory    |    -     | 

## 8. File Directory Creating

| Parameter  |                             Description                             | Comments |
|:----------:|:-------------------------------------------------------------------:|:--------:|
| `filename` |                     The directory being created                     |    -     |
|   `mode`   | Specifies the permissions to be set for the newly created directory |          |

## 9. File Directory Deleting

| Parameter  |         Description         | Comments |
|:----------:|:---------------------------:|:--------:|
| `filename` | The directory being deleted |    -     |

## 10. File Reading

| Parameter  |                        Description                         | Comments |
|:----------:|:----------------------------------------------------------:|:--------:|
|  `count`   | The maximum number of bytes that can be read from the file |    -     |
|  `inode`   |           The `inode` number of the current file           |    -     |
|   `uid`    |              The user id of the file's owner               |    -     |
|   `mode`   |               The file type and permissions                |    -     |
| `filename` |                The name of the current file                |    -     | 

## 11. File Writing

| Parameter  |                         Description                         | Comments |
|:----------:|:-----------------------------------------------------------:|:--------:|
|  `count`   | The maximum number of bytes that can be write to the file   |    -     |
|  `inode`   |           The `inode` number of the current file            |    -     |
|   `uid`    |               The user id of the file's owner               |    -     |
|   `mode`   |                The file type and permissions                |    -     |
| `filename` |                The name of the current file                 |    -     |

## 12. File Descriptor Copying

| Parameter  |                         Description                         |      Comments      |
|:----------:|:-----------------------------------------------------------:|:------------------:|
|   `olddfd`    |        A file descriptor that refers to an open directory   | As mentioned above |
|   `newdfd`(dup2)    |        A file descriptor that refers to an open directory   | As mentioned above |

## 13. File Closing

| Parameter  |                         Description                         |      Comments      |
|:----------:|:-----------------------------------------------------------:|:------------------:|
|   `dfd`    |        A file descriptor that refers to an open directory   | As mentioned above |

## 14. File Truncating

| Parameter  |                         Description                         |      Comments      |
|:----------:|:-----------------------------------------------------------:|:------------------:|
|   `dfd`(ftruncate)    |        A file descriptor that refers to an open directory   | As mentioned above |
|  `path`(truncate)   |          The path and name of the file to be created truncated          |         -          |
|  `length`  |                  The size of new file                       |         -          |

## 15. File Creating Link 

| Parameter       |                              Description                                    | Comments |
|:---------------:|:---------------------------------------------------------------------------:|:--------:|
| `olddfd`(linkat)| The file descriptor of the directory containing the file to be created link |    -     |
| `oldname`       |              The path and name of the file to be created link               |    -     |
| `newdfd`(linkat)|  The file descriptor of the directory where the file will be linked to      |    -     |
| `newname`       |                        The new name of the file                             |    -     |
|  `flags`(linkat)|               Additional behavior for creating link of the file             |    -     |

## 16. File Create Symbolic Link

| Parameter       |                              Description                                    | Comments |
|:---------------:|:---------------------------------------------------------------------------:|:--------:|
| `oldname`       |              The path and name of the file to be created symbolic link               |    -     |
| `newdfd`(symlinkat)|  The file descriptor of the directory where the file will be linked to      |    -     |
| `newname`       |                        The new name of the file                             |    -     |