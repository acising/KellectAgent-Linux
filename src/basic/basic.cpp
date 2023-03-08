//
// Created by zhuzhiling on 9/7/22.
//
#include <array>
#include <iostream>
#include <unistd.h>
#include <sys/time.h>
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

long int getCurrentTimestamp(int type) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if(type == TIMESTAMP_MILLISECOND){
        return tv.tv_sec*1000 + tv.tv_usec/1000;
    }else if(type == TIMESTAMP_MICROSECOND){
        return tv.tv_sec*10000000 + tv.tv_usec;
    }else{
        return 0;
    }
}

std::string getFormatTime(){
    struct tm *tm;
    char ts[32];
    time_t t;
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    return ts;
}
