//
// Created by zhuzhiling on 9/7/22.
//
#include <array>
#include <iostream>
#include <unistd.h>
#include <sys/utsname.h>
#include "../include/basic.h"

void info() {
    struct utsname utsname;
    uname(&utsname);

    std::cerr << "System" << std::endl
              << "  OS: " << utsname.sysname << " " << utsname.release << " "
              << utsname.version << std::endl
              << "  Arch: " << utsname.machine << std::endl;
}

bool is_root() {
    if (geteuid() != 0) {
        std::cerr << "kellect currently only supports running as the root user." << std::endl;
        return false;
    } else
        return true;
}