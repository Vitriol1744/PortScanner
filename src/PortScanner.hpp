#pragma once

#include <string_view>
#include <vector>
#include <iostream>
#include <cstdint>
#include <set>

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
        PortScanner() = default;
        
        void ParsePortsToScan(char* ports);

        void ScanPorts(std::vector<IpAddress> addresses);
        bool PortIsOpen(IpAddress ip, uint16_t port);

    private:
        std::set<int> portsToScan;
 //       std::vector<std::future<void>> futures;
   //     std::atomic<int> openedSockets = 0;

        bool Ping(std::string_view target);
};
