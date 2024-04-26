#include "PortScanner.hpp"
#include "Logger.hpp"
#include "Timer.hpp"

#include <unistd.h>
#include <getopt.h>

void help()
{
    printf("Usage: fastscan <flags> <targets>\n");
    printf("\t-p - ports to scan\n");
    printf("\texample:\t-p12,43,56-234\n");
    printf("\t-t - number of concurrent threads\n");
}

int main(int argc, char** argv)
{
    option options[] = {
        { "ports", required_argument, 0, 'c' },
        { "threads", required_argument, 0, 't' },
        { "help", no_argument, 0, 'h' },
    };
    Timer timer;
    if (argc < 2) help();
    std::vector<std::string_view> args(argv + 1, argv + argc);
    std::set<Target> targets;
    u16 threads = 64;
    char* ports = nullptr;
    int nmapArgsIndex = -1;

    int optionIndex = 0;
    while (true)
    {
        int c = getopt_long(argc, argv, "p:t:h", options, &optionIndex);
        if (c == -1) break;
        switch (c)
        {
            case 'p':
                ports = optarg;
                break;
            case 't':
                threads = atoi(optarg);
                break;
            case 'h':

            default:
                help();
                return EXIT_FAILURE;
        }
    }
    if (optind < argc)
    {
        while (optind < argc)
        {
            targets.insert(std::string_view(argv[optind++]));
        }
    }
    else
    {
        LogError("No targets specified");
        return EXIT_FAILURE;
    }

    //PortScanner scanner(threads > 64 ? 64 : threads);
    PortScanner::Initialize(threads > 64 ? 64 : threads);
    if (ports)
        PortScanner::ParsePortsToScan(ports);
    PortScanner::Scan(targets);

    LogInfo("Finished in {}s\n", timer.Elapsed().Seconds());
    return EXIT_SUCCESS;
}
