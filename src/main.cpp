#include "PortScanner.hpp"
#include "Logger.hpp"

#include <cstdlib>
#include <cctype>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <oping.h>
#include <chrono>

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
}

int main(int argc, char** argv)
{
    if (argc < 2) help();
    std::vector<std::string_view> args(argv + 1, argv + argc);
    std::vector<IpAddress> addresses;
    int threads = 64;
    char* ports = nullptr;
    for (int i = 1; i < argc; i ++)
    {
        if (compareFlag(argv[i], "-p")) 
        {
            ports = (char*)getArgument(argv, i);
        }
        else if (compareFlag(argv[i], "-t"))
                threads = atoi((char*)getArgument(argv, i));
        else if (compareFlag(argv[i], "-h"))
            help();
        else
            addresses.push_back(std::string_view(argv[i]));
    }


    PortScanner scanner(threads);
    if (ports)
        scanner.ParsePortsToScan(ports);
    scanner.ScanPorts(addresses);

    return EXIT_SUCCESS;
}
