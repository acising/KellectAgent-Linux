//
// Created by zhuzhiling on 9/7/22.
//

#ifndef KELLECT_LINUX_BASIC_H
#define KELLECT_LINUX_BASIC_H

enum class OutputBufferConfig {
    UNSET = 0,
    LINE,
    FULL,
    NONE,
};

enum class TestMode
{
    UNSET = 0,
    SEMANTIC,
    CODEGEN,
};

enum class BuildMode
{
    // Compile script and run immediately
    DYNAMIC = 0,
    // Compile script into portable executable
    AHEAD_OF_TIME,
};

enum Options
{
    INFO,
    HELP,
    VERSION,
};
bool is_root();
void info();

#endif //KELLECT_LINUX_BASIC_H