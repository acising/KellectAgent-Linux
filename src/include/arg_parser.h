// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Created by zhuzhiling on 9/7/22.
//
#include <string>
#ifndef KELLECT_LINUX_ARG_PARSER_H
#define KELLECT_LINUX_ARG_PARSER_H

struct Args {
    std::string pid_str;
    std::string cmd_str;
    bool listing = false;
    bool usdt_file_activation = false;
    int helper_check_level = 0;
    std::string filename;
    std::string event_type;
    bool if_output_to_file = false;
    bool if_output_as_json = false;
    std::string output_file;
    bool if_debug_mode = false;
};

Args parse_args(int argc, char* argv[]);
void usage();

#endif //KELLECT_LINUX_ARG_PARSER_H