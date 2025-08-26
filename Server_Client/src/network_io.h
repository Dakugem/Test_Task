#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>

namespace IO_Utils
{
    constexpr size_t BUFF_SIZE = 1024;

    class Socket
    {
        uint32_t ip;
        uint16_t port;

    public:
        Socket() : ip(0), port(0) {}
        Socket(uint32_t ip, uint16_t port) : ip(ip), port(port) {}

        uint32_t get_addr_ip() const { return ip; }
        uint16_t get_addr_port() const { return port; }

        std::string get_addr_to_str();
        bool set_addr_from_str(std::string address);

        // bool operator==(const Socket& other);
    };

    class Packet
    {
    protected:
        Socket socket;
        std::vector<uint8_t> data;

    public:
        Packet(Socket socket) : socket(socket) {}

        const Socket get_socket() const { return socket; }
        void set_socket(Socket socket) { this->socket = socket; }

        const std::vector<uint8_t> get_data() const { return data; }
        void set_data(std::vector<uint8_t> data) { this->data = data; }
    };

    class Connection
    {
    protected:
        Socket socket;
        int fd;

    public:
        Connection() : fd(-1), socket(Socket()) {};

        int get_fd() { return fd; }
        Socket get_socket() { return socket; }

        virtual int send_packet(const Packet &packet) = 0;
        virtual int recv_packet(Packet &packet) = 0;

        Connection(const Connection &) = delete;
        Connection &operator=(const Connection &) = delete;

        virtual ~Connection() = default;
    };

    enum TCP_Connection_Method
    {
        Listen,
        Connect
    };

    class TCP_Connection : public Connection
    {
        int listen();
        int connect();
        int accept(TCP_Connection& tcp_connection) const;

    public:
        TCP_Connection() : Connection() {}
        TCP_Connection(Socket socket, TCP_Connection_Method method);
        // Попробую принимать соединения через конструктор копирования
        TCP_Connection(const TCP_Connection &tcp_connection);

        int send_packet(const Packet &packet) override;
        int recv_packet(Packet &packet) override;

        ~TCP_Connection();
    };
}