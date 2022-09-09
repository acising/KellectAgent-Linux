//
// Created by zhuzhiling on 9/7/22.
//
#include <array>
#include <iostream>
#include <getopt.h>
#include "../include/arg_parser.h"
#include "../include/basic.h"

Args parse_args(int argc, char* argv[])
{
    Args args;

    const char* const short_options = "f:o:e:hlV";
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
                std::cout << "kellect " << " v1.0" << std::endl;
                exit(0);
            case Options::INFO:
                info();
                exit(0);
            case 'h':
            case Options::HELP:
                usage();
                exit(0);
            case 'o':
                args.output_file = optarg;
                break;
            case 'f':
                args.output_format = optarg;
                break;
            case 'e':
                args.choose_event_type = true;
                args.event_type = optarg;
                break;
            case 'l':
                args.listing = true;
                break;
            default:
                usage();
                exit(1);
        }
    }
    std::cerr << "Kellect is starting..." << std::endl << std::endl;

    if (argc == 1) {
        usage();
        exit(1);
    }

    if (args.listing)
    {
        std::cerr << "this function is under development." << std::endl;
    }

    if (args.choose_event_type) {
        std::cerr << "you want to trace " << args.event_type << " events" << std::endl << std::endl;
    } else {
        std::cerr << "you want to trace all events" << std::endl << std::endl;
    }

    return args;
}