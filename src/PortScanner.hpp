#pragma once

#include "Timer.hpp"

#include <string_view>
#include <mutex>
#include <cstdint>
#include <set>
#include <queue>

using usize = size_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i32 = int32_t;

inline constexpr const usize BIT(u32 n) { return 1 << n; }

enum class Flags
{
    eNone = BIT(0),
    eNoNmap = BIT(1),
};

struct Options
{
    std::set<u16> ports;
    u16 threads;

    void ParsePorts(char* ports);
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
    std::set<u16> openPorts;
};
struct Socket
{
    Socket(Target& target, i32 port) : sock(-1), target(target), port(port) { }
    ~Socket();
    //Socket (const Socket&) = delete;
    //Socket& operator= (const Socket&) = delete;
    
    void Connect(Target& target, i32 port);

    i32 sock;
    Target& target;
    i32 port;
    Timer timer;

    bool IsConnected();
};
struct SocketQueue
{
    void Push(Socket& socket);
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

namespace PortScanner
{
        void Initialize(u16 threadCount, Flags flags);
        
        void ParsePortsToScan(char* ports);

        void Scan(std::set<Target>& targets);
        void ScanPorts(std::set<Target>& targets);

        bool Ping(std::string_view target);
};
