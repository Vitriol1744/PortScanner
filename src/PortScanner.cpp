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

char* parseInt(char*& str)
{
    char* start = str;
    while (isdigit(*str)) str++;
    
    return start;
}

void PortScanner::ParsePortsToScan(char* ports)
{
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

void Scan(PortScanner* scanner, IpAddress host, std::vector<int>* ports)
{
    for (auto port : *ports)
    {
        if (scanner->PortIsOpen(host, port))
            LogInfo("{}: Port {} is open", std::string_view(host), port);
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

    auto scanPort = [this](IpAddress ip, int port){
        if (PortIsOpen(ip, port))
            LogInfo("{}: Port {} is open", std::string_view(ip), port);
    };

    int maxThreads = 64;//std::thread::hardware_concurrency();
    std::vector<int> ports[maxThreads];
    int i = 0;
    for (auto port : portsToScan)
    {
        if (i >= maxThreads) i = 0;
        ports[i].push_back(port);
        i++;
    }
    auto scan = [](PortScanner* scanner, IpAddress& host, std::vector<int>& ports)
        {
            for (auto port : ports)
            {
                if (scanner->PortIsOpen(host, port))
                    LogInfo("{}: Port {} is open", std::string_view(host), port);
            }
        };
    for (auto host : aliveHosts)
    {
        LogTrace("Scanning {}...", std::string_view(host));
        std::thread threads[maxThreads];
        for (int i = 0; i < maxThreads; i++) threads[i] = std::thread(Scan, this, IpAddress(host), &ports[i]);
        for (int i = 0; i < maxThreads; i++) threads[i].join();
        /*for (auto port : portsToScan)
        {
             futures.push_back(std::async(std::launch::async, scanPort, IpAddress(host), port));
        }*/
    }
};

bool PortScanner::PortIsOpen(IpAddress ip, uint16_t port)
{
    const char* target = ip.addr.data();

    sockaddr_in target_address{};
    target_address.sin_family = AF_INET;
    target_address.sin_port = htons(port);
    if (inet_pton(PF_INET, target, &target_address.sin_addr) <= 0)
    {
        LogError("Invalid IP address\n");
        return false;
    }

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    //fcntl(sock, F_SETFL, O_NONBLOCK);
    if (sock < 0)
    {
        LogError("Socket could not be create: {}\n", strerror(errno));
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr*)&target_address, sizeof(target_address)) == 0)
    {
        close(sock);
        return true;
    };

    close(sock);
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
