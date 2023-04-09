#include <array>
#include <iostream>
#include <fstream>
#include "include/arg_parser.h"
#include "include/basic.h"
#include "include/main.h"


int main(int argc, char* argv[]) {

    int err;
    if(is_root()){
        const Args args = parse_args(argc, argv);
        std::cerr << "Kellect is starting..." << std::endl << std::endl;
        if(args.event_type.empty() || args.event_type == "all"){
            std::cerr << "Kellect is listening events of file/process/network..." << std::endl << std::endl;
            test_all(args);
        }else if(args.event_type == "process"){
            std::cerr << "Kellect is listening events of process..." << std::endl << std::endl;
            test_process(args);
        }else if(args.event_type == "file"){
            std::cerr << "Kellect is listening events of file..." << std::endl << std::endl;
            test_file(args);
        }else if(args.event_type == "network"){
            std::cerr << "Kellect is listening events of network..." << std::endl << std::endl;
            test_network(args);
        }
    }else {
        std::cout << "please run as root" << std::endl;
    }
    return 0;

}
