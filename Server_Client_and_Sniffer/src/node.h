#pragma once

#include "network_io.h"
#include "registrar.h"

#include <memory>
#include <atomic>
#include <unordered_map>

class Node{
public:
    virtual void run(std::atomic<bool>& stop) = 0;
    virtual ~Node() = default;
};

class Server : public Node{
    IO_Utils::Socket server_address;
    std::unique_ptr<IO_Utils::TCP_Connection> server_connection;

    std::unique_ptr<IO_Utils::Registrar> registrar;
    std::unordered_map<int, std::unique_ptr<IO_Utils::TCP_Connection>> connections;

    bool accept_client();
public:
    Server(IO_Utils::Socket server_address);

    void run(std::atomic<bool>& stop) override;

    ~Server();
};

class Client : public Node{
    IO_Utils::Socket server_address;
    size_t amount_of_connections;
    size_t seed;

    std::unique_ptr<IO_Utils::Registrar> registrar;
    std::unordered_map<int, std::unique_ptr<IO_Utils::TCP_Connection>> connections;

    bool connect_client();
    IO_Utils::Packet generate_packet();
public:
    Client(IO_Utils::Socket server_address, size_t amount_of_connections, size_t seed);

    void run(std::atomic<bool>& stop) override;

    ~Client();
};