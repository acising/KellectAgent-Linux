# KellectAgent-Linux — Network Events

> Part of the [KellectAgent-Linux documentation](../README.md).

### Network (12 syscall-level + 6 kernel-level types)

Syscall level (`-e network` / `-e all`): `CONNECT`, `ACCEPT`, `ACCEPT4`, `BIND`, `GETPEERNAME`, `SOCKETPAIR`, `DS_SENDTO`, `DS_RECVFROM`, `DS_SENDMSG`, `DS_RECVMSG`, `DS_SENDMMSG` (SENDMMSG), `DS_RECVMMSG`.

Kernel level (`-e all` only, closes the connection lifecycle): `TCP_IPv4`, `TCP_IPv6`, `Connect_Failed` (synchronous failures with target address), `TCP_Disconnect` (state-machine close, no double reporting with Connect_Failed), `TCP_Retransmit` (including SYN retransmits), `UDP_SendMsg`.

