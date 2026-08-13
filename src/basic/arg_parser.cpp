//
// Created by zhuzhiling on 9/7/22.
//
#include <array>
#include <iostream>
#include <getopt.h>
#include <string.h>
#include <fstream>
#include <cstdlib>
#include <vector>
#include "../include/arg_parser.h"
#include "../include/basic.h"

// v1 filter list parsing: comma-separated and/or repeated flags -> vector
static void parse_int_list(const char *s, std::vector<int> &out) {
    const char *p = s;
    while (p && *p) {
        char *end = nullptr;
        long v = strtol(p, &end, 10);
        if (end == p) {
            std::cerr << "invalid pid list: " << s << std::endl;
            exit(1);
        }
        out.push_back(static_cast<int>(v));
        p = end;
        if (*p == ',') {
            p++;
        } else if (*p != '\0') {
            std::cerr << "invalid pid list: " << s << std::endl;
            exit(1);
        }
    }
}

static void parse_str_list(const char *s, std::vector<std::string> &out) {
    std::string ss(s);
    size_t start = 0;
    while (start <= ss.size()) {
        size_t comma = ss.find(',', start);
        if (comma == std::string::npos) {
            out.push_back(ss.substr(start));
            break;
        }
        out.push_back(ss.substr(start, comma - start));
        start = comma + 1;
    }
}

Args parse_args(int argc, char* argv[])
{
    Args args;

    const char* const short_options = "c:f:o:e:hlVdp:";
    option long_options[] = {
            option{ "help",         no_argument,       nullptr, Options::HELP },
            option{ "version",      no_argument,       nullptr, Options::VERSION },
            option{ "info",         no_argument,       nullptr, Options::INFO },
            option{ "pid",          required_argument, nullptr, 'p' },
            option{ "exclude-pid",  required_argument, nullptr, Options::EXCLUDE_PID },
            option{ "comm",         required_argument, nullptr, Options::COMM },
            option{ "exclude-comm", required_argument, nullptr, Options::EXCLUDE_COMM },
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
                if (strcmp(optarg,"text") != 0 && strcmp(optarg, "json")!=0 && strcmp(optarg,"origin") != 0){
                    std::cerr << "please input valid output format('text' or 'json')" << std::endl;
                    exit(1);
                }else if(strcmp(optarg, "json") == 0){
                    args.if_output_as_json = true;
                }else if(strcmp(optarg,"origin") == 0){
		    args.if_output_as_origin = true;
		    std::cerr<<args.if_output_as_origin;
		}
                break;
            case 'e':
                if (strcmp(optarg, "all") != 0
                    && strcmp(optarg, "process") != 0
                    && strcmp(optarg, "file") != 0
                    && strcmp(optarg, "network") != 0
                    && strcmp(optarg, "user") != 0
		    && strcmp(optarg,"conf")!=0
                    && strcmp(optarg, "image") != 0) {
                    std::cerr << "please enter a valid event type('all' or 'process' or 'file' or 'network' or 'memory')" << std::endl;
                    exit(1);
                }else {
                    args.event_type = optarg;
                }
                break;
	    case 'c':
		if(strcmp(optarg,"custom")==0)args.if_output_as_custom=true;
		args.event_type="conf";	
		break;
            case 'l':
                args.listing = true;
                break;
            case 'd':
                args.if_debug_mode = true;
                break;
            case 'p':
                parse_int_list(optarg, args.include_pids);
                break;
            case Options::EXCLUDE_PID:
                parse_int_list(optarg, args.exclude_pids);
                break;
            case Options::COMM:
                parse_str_list(optarg, args.include_comms);
                break;
            case Options::EXCLUDE_COMM:
                parse_str_list(optarg, args.exclude_comms);
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
