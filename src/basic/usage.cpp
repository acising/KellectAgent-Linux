//
// Created by zhuzhiling on 9/7/22.
//

#include <iostream>

void usage()
{
    // clang-format off
    std::cerr << "USAGE:" << std::endl;
    std::cerr << "    kellect [options] " << std::endl;
    std::cerr << "    kellect [options] filename" << std::endl;
    std::cerr << std::endl;
    std::cerr << "OPTIONS:" << std::endl;
    std::cerr << "    -f FORMAT          output format ('text', 'json')" << std::endl;
    std::cerr << "    -o file            redirect kellect output to file" << std::endl;
    std::cerr << "    -e [event_type]    choose the type of event which you want to trace" << std::endl;
    std::cerr << "        all            (default)" << std::endl;
    std::cerr << "        process        " << std::endl;
    std::cerr << "        file           " << std::endl;
    std::cerr << "        network        " << std::endl;
    std::cerr << "        memory         " << std::endl;
    std::cerr << "    -h, --help         show this help message" << std::endl;
    std::cerr << "    -l [search]        list probes" << std::endl;
    std::cerr << "    --info             Print information about kernel BPF support" << std::endl;
    std::cerr << "    -V, --version      kellect version" << std::endl;
    std::cerr << std::endl;
    // clang-format on
}