#pragma once

#include <string_view>
#include <vector>
#include <iostream>
#include <cstdint>
#include <set>
#include <future>
#include <queue>

struct Socket
{
    int sock;
    const char* target;
    int port;

    bool IsConnected();
};

struct IpAddress
{
    //TODO: Validate ip addresses
    IpAddress(std::string_view addr)
        : addr(addr) { }

    enum class Type
    {
        eV4,
        eV6
    };

    operator std::string_view() const { return addr; }

    std::string_view addr;
};

inline std::ostream& operator<<(std::ostream& os, const IpAddress& ip)
{
    os << ip.addr;
    return os;
}

class PortScanner
{
    public:
        PortScanner(int threadCount)
            : threadCount(threadCount) { threads.resize(threadCount); }
        
        void ParsePortsToScan(char* ports);

        void ScanPorts(std::vector<IpAddress> addresses);
        static bool PortIsOpen(IpAddress ip, uint16_t port);

    private:
        int threadCount;
        std::vector<std::thread> threads;
        std::set<int> portsToScan;
        std::vector<std::future<void>> futures;
        static std::queue<Socket> sockets;

        bool Ping(std::string_view target);
};
