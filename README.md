# **Kellect-Linux** : a **K**ernel-based Efficient and **L**oss**l**ess Event Log Coll**ec**tor for Linux

![](http://121.40.168.60/kellect/kellect.jpeg)

## kellect Introduction


**Kellect** means a **K**ernel-based efficient and **L**oss**l**ess event log coll**ec**tor which is a systematic framework for the full processing on kernel level logs, including collection, cleanup, confusion, storage, and analysis.

As a firstborn version, [Kellect](https://github.com/acising/kellect/) is a multi-threaded Windows kernel log collector based on ETW(BaseEvent Tracing for Windows), developed in C++ language with high-efficient performance. kellect can track kernel-level information of Windows system, such as FileIO, Process, Thread, ImageLoad, Registry, and so on.

With the help of **eBPF**(**e**xtended **B**erkeley **P**acket **F**ilter) Kellect-Linux implements the kernel-level event tracing on Linux system.

## How to use it
~~~
cd src
make kellect
./release/kellect
~~~