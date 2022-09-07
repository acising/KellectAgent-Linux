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
    }else {
        std::cout << "please run as root" << std::endl;
    }
    std::cout << "hello!" << std::endl;
    //test_demo();
    return 0;

}
