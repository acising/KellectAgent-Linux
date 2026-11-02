# KellectAgent-Linux — Image & Injection Events

> Part of the [KellectAgent-Linux documentation](../README.md).

### Image & injection (5 event types, `-e image`)

|      Event       |                      Description                       |
|:----------------:|:------------------------------------------------------:|
|   Image_Load     |  mmap with PROT_EXEC; path resolved via readlink + `/proc/<pid>/maps` fallback, with `<anonymous>` marking for JIT/packer memory |
|  Image_Mprotect  |  mprotect granting PROT_EXEC on existing memory — `RW -> RWX` on anonymous memory is flagged as the strongest injection signal  |
|   Image_Unload   |  munmap of a tracked executable mapping (registry-based, no noise from ordinary frees) |
|  Module_Load / Module_Unload | kernel module load/unload with taints (rootkit surface) |

