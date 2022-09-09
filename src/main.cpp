#include <array>
#include <iostream>
#include "include/arg_parser.h"
#include "include/basic.h"
extern "C" {
#include "include/main.h"
}


int main(int argc, char* argv[]) {

    int err;

    if(is_root()){
        const Args args = parse_args(argc, argv);
        if(args.choose_event_type){
            if(args.event_type == "all" || args.event_type == "process"){
                test_demo();
            }else{
                std::cerr << "this type of event is still under development" << std::endl;
            }
        }

    }else {
        std::cout << "please run as root" << std::endl;
    }
    return 0;

}
