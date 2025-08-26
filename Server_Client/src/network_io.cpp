#include "network_io.h"

#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

namespace IO_Utils
{
    std::string Socket::get_addr_to_str()
    {
        char ipv4_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip, ipv4_str, INET_ADDRSTRLEN);

        std::string result{ipv4_str};
        result += ":";
        result += std::to_string(port);
        return result;
    }

    bool Socket::set_addr_from_str(std::string address)
    {
        size_t index = address.rfind(':');
        if (index == std::string::npos)
            return false;

        std::string host_str = address.substr(0, index);
        std::string port_str = address.substr(index + 1);

        struct addrinfo hints, *res = nullptr;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &res);
        if (status != 0)
            return false;

        for (struct addrinfo *p = res; p != nullptr; p = p->ai_next)
        {
            if (p->ai_family == AF_INET)
            {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                
                this->ip = ipv4->sin_addr.s_addr;   
                this->port = ntohs(ipv4->sin_port); 

                freeaddrinfo(res);
                return true;
            }
        }

        freeaddrinfo(res);
        return false;
    }

    /*
    bool Socket::operator==(const Socket& other){
        return this->ip == other.ip && this->port == other.port;
    }*/

    static int set_nonblocking(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1)
            return -1;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    TCP_Connection::TCP_Connection(Socket socket, TCP_Connection_Method method)
    {
        this->socket = socket;

        int fd;
        switch (method)
        {
        case TCP_Connection_Method::Listen:
            fd = listen();
            break;
        case TCP_Connection_Method::Connect:
            fd = connect();
            break;
        default:
            fd = -1;
            break;
        }

        if (fd < 1)
        {
            // error
        }

        this->fd = fd;
    }

    TCP_Connection::TCP_Connection(const TCP_Connection &tcp_connection)
    {
        tcp_connection.accept(*this);
    }

    int TCP_Connection::listen()
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
        {
            close(fd);
            return -1;
        }

        int reuse = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)))
        {
            close(fd);
            return -2;
        }

        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = this->socket.get_addr_ip();
        address.sin_port = htons(this->socket.get_addr_port());

        if (bind(fd, (sockaddr *)&address, sizeof(address)) == -1)
        {
            close(fd);
            return -3;
        }

        if (set_nonblocking(fd) == -1)
        {
            close(fd);
            return -4;
        }

        if (::listen(fd, 5) == -1)
        {
            close(fd);
            return -5;
        }

        return fd;
    }

    int TCP_Connection::connect()
    {
        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = this->socket.get_addr_ip();
        address.sin_port = htons(this->socket.get_addr_port());

        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
        {
            close(fd);
            return -2;
        }

        if (::connect(fd, (sockaddr *)&address, sizeof(address)) == -1)
        {
            close(fd);
            return -3;
        }

        return fd;
    }

    int TCP_Connection::accept(TCP_Connection &tcp_connection) const
    {
        sockaddr_in address;
        socklen_t addrlen = sizeof(address);

        int fd = ::accept(this->fd, (sockaddr *)&address, &addrlen);
        if (fd == -1)
        {
            close(fd);
            return -1;
        }

        if (set_nonblocking(fd) == -1)
        {
            close(fd);
            return -2;
        }

        tcp_connection.fd = fd;
        tcp_connection.socket = Socket(address.sin_addr.s_addr, ntohs(address.sin_port));

        return 0;
    }

    int TCP_Connection::send_packet(const Packet &packet)
    {
        std::vector<uint8_t> data = packet.get_data();
        int send_bytes = send(fd, data.data(), data.size(), 0);

        if (send_bytes > 0)
        {
            if ((size_t)send_bytes < data.size())
            {
                return -2;
            }
        }
        else
        {
            return -1;
        }

        return 0;
    }

    int TCP_Connection::recv_packet(Packet &packet)
    {
        char buffer[BUFF_SIZE];

        int recv_bytes = recv(fd, buffer, BUFF_SIZE, 0);

        if (recv_bytes >= 0)
        {
            std::vector<uint8_t> data;

            for (size_t i = 0; i < (size_t)recv_bytes; ++i)
            {
                data.push_back(buffer[i]);
            }

            packet.set_data(data);

            return 0;
        }
        else
        {
            return -1;
        }
    }

    TCP_Connection::~TCP_Connection()
    {
        if (fd > 0)
        {
            if (close(fd) == -1)
            {
                // error
            }
        }
    }
}