#include "PortScanner.hpp"

#include <cstdlib>
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
const char* GetArgument(char** argv, int& i)
{

    while (*argv[i])
    {
        if (isdigit(*argv[i])) return argv[i];
        argv[i]++;
    }

    return argv[++i];
}

int main(int argc, char** argv)
{
    std::vector<std::string_view> args(argv + 1, argv + argc);
    std::vector<IpAddress> addresses;
    PortScanner scanner;
    for (int i = 1; i < argc; i ++)
    {
        if (compareFlag(argv[i], "-p")) 
        {
            char* ports = (char*)GetArgument(argv, i);
            scanner.ParsePortsToScan(ports);
        }
        else
            addresses.push_back(std::string_view(argv[i]));
    }


    scanner.ScanPorts(addresses);

    return EXIT_SUCCESS;
}
