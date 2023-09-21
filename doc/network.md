# Details of Network Event

## 1. Connection Establishing

| Parameter  |            Description            |                                             Comments                                              |
|:----------:|:---------------------------------:|:-------------------------------------------------------------------------------------------------:|
|    `fd`    | The file descriptor of the socket |                                                 -                                                 |
| `addr_len` |  Length of the address structure  |                                                 -                                                 |
|  `family`  |   Address family of the socket    | IPv4 sockets has value `AF_INET`, which is `2`; IPv6 sockets has value `AF_INET6`, which is `10`; |
|   `port`   |            Port number            |                                                 -                                                 |
|   `addr`   |         IPv4/IPv6 address         |                                                 -                                                 | 

## 2. Datagram Socket Sending 

| Parameter  |                           Description                           |         Comments          |
|:----------:|:---------------------------------------------------------------:|:-------------------------:|
|    `fd`    |                The file descriptor of the socket                |             -             |
|   `len`    |              Maximum length of the data being sent              |             -             |
|  `flags`   |       A bit mask controlling socket-specific I/O features       | When not needed, set to 0 |
| `addr_len` |                 Length of the address structure                 |             -             |
|  `family`  |  Address family of the peer socket which we are communicating   |             -             |
|   `port`   |    Port number of the peer socket which we are communicating    |             -             |
|   `addr`   | IPv4/IPv6 address of the peer socket which we are communicating |             -             |

## 3. Datagram Socket Receiving 

| Parameter  |                                     Description                                      |                                                                                         Comments                                                                                          |
|:----------:|:------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    `fd`    |                          The file descriptor of the socket                           |                                                                                             -                                                                                             |
|   `len`    |                      Maximum length of the data being received                       |                                                                                             -                                                                                             |
|  `flags`   |                 A bit mask controlling socket-specific I/O features                  |                                                                                 When not needed, set to 0                                                                                 |
| `addr_len` | Length of the address structure / number of bytes actually written to this structure | Prior to the call, `addrlen` should be initialized to the size of the structure pointed to by `src_addr`; upon return, it contains the number of bytes actually written to this structure |
|  `family`  |             Address family of the peer socket which we are communicating             |                                                                                             -                                                                                             |
|   `port`   |              Port number of the peer socket which we are communicating               |                                                                                             -                                                                                             |
|   `addr`   |           IPv4/IPv6 address of the peer socket which we are communicating            |                                                                                             -           
## 4. Connection Accepting

| Parameter  |            Description            |                                             Comments                                              |
|:----------:|:---------------------------------:|:-------------------------------------------------------------------------------------------------:|
|    `fd`    | The file descriptor of the socket |                                                 -                                                 |
| `addr_len` |  Length of the address structure  |                                                 -                                                 |
|  `family`  |   Address family of the socket    | IPv4 sockets has value `AF_INET`, which is `2`; IPv6 sockets has value `AF_INET6`, which is `10`; |
|   `port`   |            Port number            |                                                 -                                                 |
|   `addr`   |         IPv4/IPv6 address         |                                                 -                                                 |
|   `flags`(accept4)   |      some properties of the socket             |                                                 When not needed, set to 0                                                 |

## 5. Socket Binding

| Parameter  |            Description            |                                             Comments                                              |
|:----------:|:---------------------------------:|:-------------------------------------------------------------------------------------------------:|
|    `fd`    | The file descriptor of the socket |                                                 -                                                 |
| `addr_len` |  Length of the address structure  |                                                 -                                                 |
|  `family`  |   Address family of the socket    | IPv4 sockets has value `AF_INET`, which is `2`; IPv6 sockets has value `AF_INET6`, which is `10`; |
|   `port`   |            Port number            |                                                 -                                                 |
|   `addr`   |         IPv4/IPv6 address         |                                                 -                                                 | 

## 6. Getting The Name Of The Connected Peer Socket

| Parameter  |            Description            |                                             Comments                                              |
|:----------:|:---------------------------------:|:-------------------------------------------------------------------------------------------------:|
|    `fd`    | The file descriptor of the socket |                                                 -                                                 |
| `addr_len` |  Length of the address structure  |                                                 -                                                 |
|  `family`  |   Address family of the socket    | IPv4 sockets has value `AF_INET`, which is `2`; IPv6 sockets has value `AF_INET6`, which is `10`; |
|   `port`   |            Port number            |                                                 -                                                 |
|   `addr`   |         IPv4/IPv6 address         |                                                 -                                                 | 

## 7. Establish a Pair Of Connected Sockets

| Parameter  |                           Description                           |         Comments          |
|:----------:|:---------------------------------------------------------------:|:-------------------------:|
|    `family`    |                protocol family of socket                |             -             |
|   `type`    |              The type of socket              |             -             |
|  `protocol`   |       0       | must set to 0 |
| `usockvec` |                 Pointer to storage file descriptor                 |             -             |

