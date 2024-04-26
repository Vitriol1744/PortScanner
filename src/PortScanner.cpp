#include "PortScanner.hpp"

#include "Logger.hpp"

#include <thread>

#include <arpa/inet.h>
#include <fcntl.h>
#include <oping.h>

static SocketQueue socketQueue{};
static u16 threadCount;
static std::vector<std::thread> threads;
static std::set<u16> portsToScan;

inline constexpr const u64 timeout = 100;

Socket::~Socket()
{
    return;
    if (IsConnected())
    {
        LogInfo("{}: Port {} is open", std::string_view(target), port);
        target.openPorts.insert(port);;
    }
}

void Socket::Connect(Target& target, i32 port)
{
    const char* addr = target.addr.data();

    sockaddr_in target_address{};
    target_address.sin_family = AF_INET;
    target_address.sin_addr.s_addr = inet_addr(addr);
    target_address.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(sock, F_SETFL, O_NONBLOCK);
    if (sock < 0)
    {
        LogError("Socket could not be create: {}\n", strerror(errno));
        return;
    }

    i32 status = connect(sock, (struct sockaddr*)&target_address, sizeof(target_address));
    if (status == -1 && errno != EINPROGRESS) close(sock);
    timer.Restart();
}

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

void PortScanner::Initialize(u16 threadCount)
{
    ::threadCount = threadCount;
    threads.resize(threadCount);
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
    for (auto target : targets)
    {
        Ping(target);
        //if (Ping(target)) 
        //    LogInfo("{} is Alive", std::string_view(target));
        //else LogInfo("{} is Down or doesn't respond to ICMP packets", std::string_view(target));
    }
    ScanPorts(targets);
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

    auto worker = [](Target target, std::vector<u16>& ports)
    {
        for (auto port : ports)
        {
            if (socketQueue.GetSize() > 512)
                socketQueue.Pop();
            Socket socket = {target, port };
            socket.Connect(target, port);
            socketQueue.Push(socket);
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

    Timer timer;
    bool ret = false;
    auto status = ping_send(pingObj);
    if (status > 0)
    {
        LogInfo("{} is Alive(replied in {:0.2f}s)", ip, timer.Elapsed().Seconds());
            ret = true;
    }
    else LogInfo("{} is Down or doesn't respond to ICMP packets", ip);
    
    ping_destroy(pingObj);
    
    return ret;
}

void SocketQueue::Push(Socket& socket)
{
    std::unique_lock guard(lock);
    sockets.push(socket);
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
