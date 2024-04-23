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

std::queue<Socket> PortScanner::sockets{};
std::mutex lock;

bool Socket::IsConnected()
{
    fd_set input;
    FD_ZERO(&input);
    FD_SET(sock, &input);
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 20 * 1000;
    int status = select(sock + 1, nullptr, &input, nullptr, &tv);
    if (status == 1)
    {
        int err = 0;
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

            int portsStart = atoi(start);
            int portsEnd = atoi(end);
            for (int i = portsStart; i <= portsEnd; i++)
                portsToScan.insert(i);
        }
    }
}

void PortScanner::ScanPorts(std::vector<IpAddress> addresses)
{
    std::set<const char*> aliveHosts;
    for (auto ip : addresses)
    {
        if (Ping(ip)) 
        {
            aliveHosts.insert(ip.addr.data());
            LogInfo("{} is Alive", std::string_view(ip));
        }
        else LogInfo("{} is Down", std::string_view(ip));

    }

    std::vector<int> ports[threadCount];
    int i = 0;
    // Divide work for threads
    for (auto port : portsToScan)
    {
        if (i >= threadCount) i = 0;
        ports[i].push_back(port);
        i++;
    }
    auto scan = [](IpAddress host, std::vector<int>* ports)
    {
        for (auto port : *ports)
        {
            if (sockets.size() > 512)
            {
                lock.lock();
                Socket socket = sockets.front();
                sockets.pop();
                lock.unlock();
                if (socket.IsConnected())
                    LogInfo("{}: Port {} is open", socket.target, socket.port);

            }
            if (PortScanner::PortIsOpen(host, port))
 ;//               LogInfo("{}: Port {} is open", std::string_view(host), port);
        }
    };
    auto scanPort = [](IpAddress addr, int port)
        {
            if (PortIsOpen(addr, port)) 
                LogInfo("{}: Port {} is open", std::string_view(addr), port);
        };
    for (auto host : aliveHosts)
    {
        LogTrace("Scanning {}...", std::string_view(host));
        for (int i = 0; i < threadCount; i++) threads[i] = std::thread(scan, IpAddress(host), &ports[i]);
        for (int i = 0; i < threadCount; i++) threads[i].join();
        //for (auto port : portsToScan)
        //{
        //     futures.push_back(std::async(std::launch::async, scanPort, IpAddress(host), port));
        //}
    }
};

bool PortScanner::PortIsOpen(IpAddress ip, uint16_t port)
{
    const char* target = ip.addr.data();

    sockaddr_in target_address{};
    target_address.sin_family = AF_INET;
    target_address.sin_addr.s_addr = inet_addr(target);
    target_address.sin_port = htons(port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(sock, F_SETFL, O_NONBLOCK);
    if (sock < 0)
    {
        LogError("Socket could not be create: {}\n", strerror(errno));
        close(sock);
        return false;
    }

    int status = connect(sock, (struct sockaddr*)&target_address, sizeof(target_address));
    if (status == -1 && errno != EINPROGRESS)
    {
        close(sock);
        return false;
    }
    else if (status == 0)
    {
        close(sock);
        return true;
    };

    lock.lock();
    sockets.push({sock, target, port});
    size_t queueSize = sockets.size();
    lock.unlock();
    /*if (queueSize > 64)
    {
        lock.lock();
        Socket socket = sockets.front();
        sock = socket.sock;
        sockets.pop();
        lock.unlock();
        return socket.IsConnected();
    }*/
    return false;
}

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
