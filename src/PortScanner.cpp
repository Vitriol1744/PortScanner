#include "PortScanner.hpp"

#include "Logger.hpp"

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
#include <set>
#include <thread>
#include <queue>

static SocketQueue socketQueue{};

bool Socket::IsConnected()
{
    fd_set input;
    FD_ZERO(&input);
    FD_SET(sock, &input);
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 20 * 1000;
    i32 status = select(sock + 1, nullptr, &input, nullptr, &tv);
    if (status == 1)
    {
        i32 err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)&err, &len);
        if (err == 0)
        {
            close(sock);
            return true;
        }
    }
    close(sock);
    return false;
}

void PortScanner::ParsePortsToScan(char* ports)
{
    auto parseInt = [](char*& str) -> char*
    {
        char* start = str;
        while (isdigit(*str)) str++;
    
        return start;
    };

    while (*ports)
    {
        char* start = parseInt(ports);
        if (*ports == ',' || *ports == 0)
        {
            if (*ports) *ports++ = 0;
            portsToScan.insert(atoi(start));
        }
        else if (*ports == '-')
        {
            *ports++ = 0;
            char* end = parseInt(ports);
            if (*ports)
            {
                if (*ports != ',') throw std::runtime_error("Invalid ports range!");
                *ports++ = 0;
            }

            u32 portsStart = atoi(start);
            u32 portsEnd = atoi(end);
            for (u32 i = portsStart; i <= portsEnd; i++)
                portsToScan.insert(i);
        }
    }
}

void PortScanner::Scan(std::set<Target>& targets)
{
    std::set<Target> aliveTargets;
    for (auto target : targets)
    {
        if (Ping(target)) 
        {
            aliveTargets.insert(target);
            LogInfo("{} is Alive", std::string_view(target));
        }
        else LogInfo("{} is Down", std::string_view(target));
    }
    ScanPorts(aliveTargets);
}

void PortScanner::ScanPorts(std::set<Target>& targets)
{
    // Divide work for threads
    std::vector<u16> ports[threadCount];
    u16 i = 0;
    for (auto port : portsToScan)
    {
        if (i >= threadCount) i = 0;
        ports[i].push_back(port);
        i++;
    }

    auto worker = [this](Target target, std::vector<u16>& ports)
    {
        for (auto port : ports)
        {
            if (socketQueue.GetSize() > 512)
                socketQueue.Pop();
            socketQueue.Push(target, port);
        }
    };
    for (auto target : targets)
    {
        LogTrace("Scanning {}...", std::string_view(target));
        for (u32 i = 0; i < threadCount; i++) threads[i] = std::thread(worker, target, std::ref(ports[i]));
        for (u32 i = 0; i < threadCount; i++) threads[i].join();
        socketQueue.Clear();
    }
};

bool PortScanner::Ping(std::string_view ip)
{
    pingobj_t * pingObj = ping_construct();
    ping_host_add(pingObj, ip.data());

    auto startTime = std::chrono::high_resolution_clock::now();
    auto ret = ping_send(pingObj);
    auto endTime = std::chrono::high_resolution_clock::now();
    if (ret > 0)
    {
        auto duration = (double)std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count()/1000.0;
        return true;
    } 
    
    ping_destroy(pingObj);
    
    return false;
}

void SocketQueue::Push(Target& target, u16 port)
{
    const char* addr = target.addr.data();

    sockaddr_in target_address{};
    target_address.sin_family = AF_INET;
    target_address.sin_addr.s_addr = inet_addr(addr);
    target_address.sin_port = htons(port);

    i32 sock = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(sock, F_SETFL, O_NONBLOCK);
    if (sock < 0)
    {
        LogError("Socket could not be create: {}\n", strerror(errno));
        return;
    }

    i32 status = connect(sock, (struct sockaddr*)&target_address, sizeof(target_address));
    if (status == -1 && errno != EINPROGRESS) goto failure;

    lock.lock();
    sockets.push({sock, target, port});
    lock.unlock();
    return;

failure:
    close(sock);
}
void SocketQueue::Pop()
{
    lock.lock();
    if (sockets.empty()) return lock.unlock();
    Socket socket = sockets.front();
    sockets.pop();
    lock.unlock();
    if (socket.IsConnected())
    {
        LogInfo("{}: Port {} is open", std::string_view(socket.target), socket.port);
        socket.target.openPorts.insert(socket.port);;
    }
}
