#pragma once

#include "queue.h"
#include "network_io.h"

#include <atomic>

class Node{
public:
    virtual void run(std::atomic<bool>& stop) = 0;
    virtual ~Node() = default;
};

class Server : public Node{
    IO_Utils::Queue<IO_Utils::Packet> in_queue{1024};
    IO_Utils::Queue<IO_Utils::Packet> out_queue{1024};
public:
    Server(IO_Utils::Socket server_address);

    void run(std::atomic<bool>& stop) override;

    ~Server();
};

class Client : public Node{
    IO_Utils::Queue<IO_Utils::Packet> in_queue{1024};
    IO_Utils::Queue<IO_Utils::Packet> out_queue{1024};
public:
    Client(IO_Utils::Socket server_address, size_t connections, size_t seed);

    void run(std::atomic<bool>& stop) override;

    ~Client();
};