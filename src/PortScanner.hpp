#pragma once

#include <string_view>
#include <vector>
#include <thread>
#include <iostream>
#include <cstdint>
#include <set>
#include <queue>

using usize = size_t;
using u16 = uint16_t;
using u32 = uint32_t;
using i32 = int32_t;

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
    std::set<u16> openPorts;
};
struct Socket
{
    i32 sock;
    Target& target;
    i32 port;

    bool IsConnected();
};
struct SocketQueue
{
    void Push(Target& target, u16 port);
    void Pop();

    inline usize GetSize() const { return sockets.size(); }
    inline bool Empty() const { return sockets.empty(); }

    inline void Clear()
    {
        while (!Empty()) Pop();
    }

    std::queue<Socket> sockets{};
    std::mutex lock;
};

inline std::ostream& operator<<(std::ostream& os, const Target& target)
{
    os << target.addr;
    return os;
}

class PortScanner
{
    public:
        PortScanner(u16 threadCount)
            : threadCount(threadCount) { threads.resize(threadCount); }
        
        void ParsePortsToScan(char* ports);

        void Scan(std::set<Target>& targets);
        void ScanPorts(std::set<Target>& targets);

    private:
        u16 threadCount;
        std::vector<std::thread> threads;
        std::set<u16> portsToScan;

        bool Ping(std::string_view target);
};
