#include "Logger.hpp"
#include "PortScanner.hpp"
#include "Timer.hpp"

#include <getopt.h>
#include <unistd.h>

void help()
{
    printf("Usage: fastscan <flags> <targets>\n");
    printf("\t-p - ports to scan\n");
    printf("\texamples:\n\t\t-p12,43,56-234\n");
    printf("\t\t-p- - scans all ports\n");
    printf("\t-t - number of concurrent threads\n");
    printf("\t-n - don't run nmap\n");
}

int main(int argc, char** argv)
{
    option options[] = {
        {"ports", required_argument, 0, 'c'},
        {"threads", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {"no-nmap", no_argument, 0, 'n'},
    };
    Timer timer;
    if (argc < 2) help();
    std::set<Target> targets;
    u16              threads     = 64;
    char*            ports       = nullptr;
    Flags            flags       = Flags::eNone;

    int              optionIndex = 0;
    while (true)
    {
        int c = getopt_long(argc, argv, "p:t:h", options, &optionIndex);
        if (c == -1) break;
        switch (c)
        {
            case 'p': ports = optarg; break;
            case 't': threads = atoi(optarg); break;
            case 'n':
                flags = static_cast<Flags>(static_cast<u32>(Flags::eNoNmap)
                                           | static_cast<u32>(flags));
                break;
            case 'h':

            default: help(); return EXIT_FAILURE;
        }
    }
    if (optind < argc)
    {
        while (optind < argc) targets.insert(std::string_view(argv[optind++]));
    }
    else
    {
        LogError("No targets specified");
        return EXIT_FAILURE;
    }

    PortScanner::Initialize(threads > 64 ? 64 : threads, flags);
    if (ports) PortScanner::ParsePortsToScan(ports);
    PortScanner::Scan(targets);

    LogInfo("Finished in {}s\n", timer.Elapsed().Seconds());
    return EXIT_SUCCESS;
}
