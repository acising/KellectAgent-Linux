#include <array>
#include <cstring>
#include <iostream>
#include <getopt.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <vector>
extern "C"{
#include "include/main.h"
}

namespace kellect{
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
        INFO = 2000,
        EMIT_ELF,
        NO_WARNING,
        TEST,
        AOT,
        HELP,
        VERSION,
        USDT_SEMAPHORE,
        UNSAFE,
        BTF,
        INCLUDE,
    };
}

using namespace kellect;

void usage()
{
    // clang-format off
    std::cerr << "USAGE:" << std::endl;
    std::cerr << "    kellect [options] filename" << std::endl;
    std::cerr << "    kellect [options] - <stdin input>" << std::endl;
    std::cerr << "    kellect [options] -e 'program'" << std::endl;
    std::cerr << std::endl;
    std::cerr << "OPTIONS:" << std::endl;
    std::cerr << "    -B MODE        output buffering mode ('full', 'none')" << std::endl;
    std::cerr << "    -f FORMAT      output format ('text', 'json')" << std::endl;
    std::cerr << "    -o file        redirect bpftrace output to file" << std::endl;
    std::cerr << "    -e 'program'   execute this program" << std::endl;
    std::cerr << "    -h, --help     show this help message" << std::endl;
    std::cerr << "    -I DIR         add the directory to the include search path" << std::endl;
    std::cerr << "    --include FILE add an #include file before preprocessing" << std::endl;
    std::cerr << "    -l [search]    list probes" << std::endl;
    std::cerr << "    -p PID         enable USDT probes on PID" << std::endl;
    std::cerr << "    -c 'CMD'       run CMD and enable USDT probes on resulting process" << std::endl;
    std::cerr << "    --usdt-file-activation" << std::endl;
    std::cerr << "                   activate usdt semaphores based on file path" << std::endl;
    std::cerr << "    --unsafe       allow unsafe builtin functions" << std::endl;
    std::cerr << "    -q             keep messages quiet" << std::endl;
    std::cerr << "    --info         Print information about kernel BPF support" << std::endl;
    std::cerr << "    -k             emit a warning when a bpf helper returns an error (except read functions)" << std::endl;
    std::cerr << "    -kk            check all bpf helper functions" << std::endl;
    std::cerr << "    -V, --version  bpftrace version" << std::endl;
    std::cerr << "    --no-warnings  disable all warning messages" << std::endl;
    std::cerr << std::endl;
    // clang-format on
}

static void info()
{
    struct utsname utsname;
    uname(&utsname);

    std::cerr << "System" << std::endl
              << "  OS: " << utsname.sysname << " " << utsname.release << " "
              << utsname.version << std::endl
              << "  Arch: " << utsname.machine << std::endl;
}

bool is_root()
{
    if (geteuid() != 0)
    {
        std::cerr << "kellect currently only supports running as the root user." << std::endl;
        return false;
    }
    else
        return true;
}

struct Args
{
    std::string pid_str;
    std::string cmd_str;
    bool listing = false;
    bool safe_mode = true;
    bool usdt_file_activation = false;
    int helper_check_level = 0;
    TestMode test_mode = TestMode::UNSET;
    std::string script;
    std::string search;
    std::string filename;
    std::string output_file;
    std::string output_format;
    std::string output_elf;
    std::string aot;
    OutputBufferConfig obc = OutputBufferConfig::UNSET;
    BuildMode build_mode = BuildMode::DYNAMIC;
    std::vector<std::string> include_dirs;
    std::vector<std::string> include_files;
    std::vector<std::string> params;
};

Args parse_args(int argc, char* argv[])
{
    Args args;

    const char* const short_options = "dbB:f:e:hlp:vqc:Vo:I:k";
    option long_options[] = {
            option{ "help", no_argument, nullptr, Options::HELP },
            option{ "version", no_argument, nullptr, Options::VERSION },
            option{
                    "usdt-file-activation", no_argument, nullptr, Options::USDT_SEMAPHORE },
            option{ "unsafe", no_argument, nullptr, Options::UNSAFE },
            option{ "btf", no_argument, nullptr, Options::BTF },
            option{ "include", required_argument, nullptr, Options::INCLUDE },
            option{ "info", no_argument, nullptr, Options::INFO },
            option{ "emit-elf", required_argument, nullptr, Options::EMIT_ELF },
            option{ "no-warnings", no_argument, nullptr, Options::NO_WARNING },
            option{ "test", required_argument, nullptr, Options::TEST },
            option{ "aot", required_argument, nullptr, Options::AOT },
            option{ nullptr, 0, nullptr, 0 }, // Must be last
    };

    int c;
    while ((c = getopt_long(
            argc, argv, short_options, long_options, nullptr)) != -1)
    {
        switch (c)
        {
            case Options::INFO: // --info
                if (is_root())
                {
                    info();
                    exit(0);
                }
                exit(1);
                break;
            case Options::EMIT_ELF: // --emit-elf
                args.output_elf = optarg;
                break;
            case Options::NO_WARNING: // --no-warnings
                usage();
                break;
            case Options::TEST: // --test
                if (std::strcmp(optarg, "semantic") == 0)
                    args.test_mode = TestMode::SEMANTIC;
                else if (std::strcmp(optarg, "codegen") == 0)
                    args.test_mode = TestMode::CODEGEN;
                else
                {
                    std::cerr << "USAGE: --test must be either 'semantic' or 'codegen'.";
                    exit(1);
                }
                break;
            case Options::AOT: // --aot
                args.aot = optarg;
                args.build_mode = BuildMode::AHEAD_OF_TIME;
                break;
            case 'o':
                args.output_file = optarg;
                break;
            case 'B':
                if (std::strcmp(optarg, "line") == 0) {
                    args.obc = OutputBufferConfig::LINE;
                } else if (std::strcmp(optarg, "full") == 0) {
                    args.obc = OutputBufferConfig::FULL;
                } else if (std::strcmp(optarg, "none") == 0) {
                    args.obc = OutputBufferConfig::NONE;
                } else {
                    std::cerr << "USAGE: -B must be either 'line', 'full', or 'none'.";
                    exit(1);
                }
                break;
            case 'f':
                args.output_format = optarg;
                break;
            case 'e':
                args.script = optarg;
                break;
            case 'p':
                args.pid_str = optarg;
                break;
            case 'I':
                args.include_dirs.push_back(optarg);
                break;
            case Options::INCLUDE:
                args.include_files.push_back(optarg);
                break;
            case 'l':
                args.listing = true;
                break;
            case 'c':
                args.cmd_str = optarg;
                break;
            case Options::USDT_SEMAPHORE:
                args.usdt_file_activation = true;
                break;
            case Options::UNSAFE:
                args.safe_mode = false;
                break;
            case 'b':
            case Options::BTF:
                break;
            case 'h':
            case Options::HELP:
                usage();
                exit(0);
            case 'V':
            case Options::VERSION:
                std::cout << "kellect " << " v0.0.1" << std::endl;
                exit(0);
            case 'k':
                args.helper_check_level++;
                if (args.helper_check_level >= 3)
                {
                    usage();
                    exit(1);
                }
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


    if (!args.cmd_str.empty() && !args.pid_str.empty())
    {
        std::cerr << "USAGE: Cannot use both -c and -p.";
        usage();
        exit(1);
    }

    // Difficult to serialize flex generated types
    if (args.helper_check_level && args.build_mode == BuildMode::AHEAD_OF_TIME)
    {
        std::cerr << "Cannot use -k[k] with --aot";
        exit(1);
    }

    if (args.listing)
    {
        // Expect zero or one positional arguments
        if (optind == argc)
        {
            args.search = "*:*";
        }
        else if (optind == argc - 1)
        {
            args.search = argv[optind];
            if (args.search == "*")
            {
                args.search = "*:*";
            }
            optind++;
        }
        else
        {
            usage();
            exit(1);
        }
    }
    else
    {
        // Expect to find a script either through -e or filename
        if (args.script.empty() && argv[optind] == nullptr)
        {
            std::cerr << "USAGE: filename or -e 'program' required.";
            exit(1);
        }

        // If no script was specified with -e, then we expect to find a script file
        if (args.script.empty())
        {
            args.filename = argv[optind];
            optind++;
        }

        // Load positional parameters before driver runs so positional
        // parameters used inside attach point definitions can be resolved.
        while (optind < argc)
        {
            args.params.push_back(argv[optind]);
            optind++;
        }
    }

    return args;
}


int main(int argc, char* argv[]) {

    int err;

    if(is_root()){
        //const Args args = parse_args(argc, argv);
    }else {
        std::cout << "please run as root" << std::endl;
    }
    std::cout << "hello!" << std::endl;
    test_demo();
    return 0;

}
