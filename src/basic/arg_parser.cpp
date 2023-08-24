//
// Created by zhuzhiling on 9/7/22.
//
#include <array>
#include <iostream>
#include <getopt.h>
#include <string.h>
#include <fstream>
#include "../include/arg_parser.h"
#include "../include/basic.h"

Args parse_args(int argc, char* argv[])
{
    Args args;

    const char* const short_options = "f:o:e:hlVd";
    option long_options[] = {
            option{ "help",    no_argument, nullptr, Options::HELP },
            option{ "version", no_argument, nullptr, Options::VERSION },
            option{ "info",    no_argument, nullptr, Options::INFO },
            option{ nullptr, 0, nullptr, 0 }, // Must be last
    };

    int c;
    while ((c = getopt_long(
            argc, argv, short_options, long_options, nullptr)) != -1)
    {
        switch (c){
            case 'V':
            case Options::VERSION:
                std::cout << "kellect for Linux" << " v1.0" << std::endl;
                exit(0);
            case Options::INFO:
                info();
                exit(0);
            case 'h':
            case Options::HELP:
                usage();
                exit(0);
            case 'o':{
                std::ofstream ofstream;
                ofstream.open(optarg, std::ios::out);
                if(!ofstream){
                    std::cerr << "please enter a valid file name/path" << std::endl;
                    exit(1);
                }
                ofstream.close();
                args.output_file = optarg;
                args.if_output_to_file = true;
                break;
            }
            case 'f':
                if (strcmp(optarg,"text") != 0 && strcmp(optarg, "json") != 0){
                    std::cerr << "please input valid output format('text' or 'json')" << std::endl;
                    exit(1);
                }else if(strcmp(optarg, "json") == 0){
                    args.if_output_as_json = true;
                }
                break;
            case 'e':
                if (strcmp(optarg, "all") != 0
                    && strcmp(optarg, "process") != 0
                    && strcmp(optarg, "file") != 0
                    && strcmp(optarg, "network") != 0
                    && strcmp(optarg, "user") != 0) {
                    std::cerr << "please enter a valid event type('all' or 'process' or 'file' or 'network' or 'memory')" << std::endl;
                    exit(1);
                }else {
                    args.event_type = optarg;
                }
                break;
            case 'l':
                args.listing = true;
                break;
            case 'd':
                args.if_debug_mode = true;
                break;
            default:
                usage();
                exit(1);
        }
    }

    if (argc == 1) {
        usage();
        exit(1);
    }

    if (args.listing)
    {
        std::cerr << "this function is under development." << std::endl;
        exit(1);
    }

    return args;
}