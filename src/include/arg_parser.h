//
// Created by zhuzhiling on 9/7/22.
//
#ifndef KELLECT_LINUX_ARG_PARSER_H
#define KELLECT_LINUX_ARG_PARSER_H
;
struct Args {
    std::string pid_str;
    std::string cmd_str;
    bool choose_event_type = false;
    bool listing = false;
    bool usdt_file_activation = false;
    int helper_check_level = 0;
    std::string filename;
    std::string event_type;
    std::string output_file;
    std::string output_format;
};

Args parse_args(int argc, char* argv[]);
void usage();

#endif //KELLECT_LINUX_ARG_PARSER_H