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

struct Target
{
    //TODO: Validate ip addresses
    Target(std::string_view addr)
        : addr(addr) { }

    enum class Type
    {
        eV4,
        eV6
    };

    operator std::string_view() const { return addr; }
    auto operator<=>(const Target& other) const
    {
        return addr <=> other.addr;
    }  
    std::string_view addr;
    std::set<int> openPorts;
};

inline std::ostream& operator<<(std::ostream& os, const Target& ip)
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

        void Scan(std::set<Target>& targets);
        void ScanPorts(std::set<Target>& targets);
        static bool PortIsOpen(Target ip, uint16_t port);

    private:
        int threadCount;
        std::vector<std::thread> threads;
        std::set<int> portsToScan;
        std::vector<std::future<void>> futures;
        static std::queue<Socket> sockets;

        bool Ping(std::string_view target);
};
