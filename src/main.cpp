#include "PortScanner.hpp"
#include "Logger.hpp"

#include <cctype>

bool compareFlag(const char* flag, const char* eq)
{
    while (*eq)
    {
        if (*flag++ != *eq++) return false;
    }

    if (!isdigit(*flag) && *flag != 0) return false;
    return true;
}
const char* getArgument(char** argv, int& i)
{

    while (*argv[i])
    {
        if (isdigit(*argv[i])) return argv[i];
        argv[i]++;
    }

    return argv[++i];
}

void help()
{
    printf("Usage: fastscan <flags> <targets>\n");
    printf("\t-p - ports to scan\n");
    printf("\texample:\t-p12,43,56-234\n");
    printf("\t-t - number of concurrent threads\n");
}

int main(int argc, char** argv)
{
    if (argc < 2) help();
    std::vector<std::string_view> args(argv + 1, argv + argc);
    std::set<Target> targets;
    int threads = 64;
    char* ports = nullptr;
    int nmapArgsIndex = -1;

    for (int i = 1; i < argc; i ++)
    {
        if (strcmp(argv[i], "--") == 0)
        {
            nmapArgsIndex = i + 1;
            break;
        }
        else if (compareFlag(argv[i], "-p")) 
        {
            ports = (char*)getArgument(argv, i);
        }
        else if (compareFlag(argv[i], "-t"))
                threads = atoi((char*)getArgument(argv, i));
        else if (compareFlag(argv[i], "-h"))
            help();
        else
        {
            std::string_view target(argv[i]);
            for (auto c : target)
            {
                if (!isdigit(c) && c != '.')
                {
                    LogError("{}: Invalid Target ip address!", target);
                    return EXIT_FAILURE;
                }
            }
            targets.insert(target);
        }
    }


    PortScanner scanner(threads);
    if (ports)
        scanner.ParsePortsToScan(ports);
    scanner.Scan(targets);

    return EXIT_SUCCESS;
}
