#include "node.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <stdexcept>
#include <cerrno>
#include <iostream>
#include <format>
#include <cstdlib>

Server::Server(IO_Utils::Socket server_address) : server_address(server_address)
{
    errno = 0;
    registrar = std::make_unique<IO_Utils::Registrar>();
    if (registrar->get_epoll_fd() < 0)
    {
        throw std::runtime_error(std::format("Can't create registrar correctly with errno = {}", errno));
    }

    errno = 0;
    server_connection = std::make_unique<IO_Utils::TCP_Connection>(server_address, IO_Utils::TCP_Connection_Method::Listen);
    if (server_connection->get_fd() < 0)
    {
        throw std::runtime_error(std::format("TCP server listening failure with errno = {}", errno));
    }

    errno = 0;
    if (registrar->register_socket(server_connection->get_fd(), EPOLLIN) < 0)
    {
        throw std::runtime_error(std::format("TCP server register failure with errno = {}", errno));
    }
}

void Server::run(std::atomic<bool> &stop)
{
    epoll_event events[IO_Utils::MAX_EVENTS];

    while (!stop.load())
    {
        errno = 0;
        int nfds = epoll_wait(registrar->get_epoll_fd(), events, IO_Utils::MAX_EVENTS, IO_Utils::TIMEOUT);
        if (nfds < 0)
        {
            if (errno = EINTR)
            {
                // Its okay, program was interrupted
            }
            else
            {
                std::cerr << std::format("Epoll_wait error, epoll_fd = {}, errno = {}", registrar->get_epoll_fd(), errno) << std::endl;
            }
        }

        for (int i = 0; i < nfds; ++i)
        {
            int fd = events[i].data.fd;

            if (fd == server_connection->get_fd())
            {
                if ((events[i].events & EPOLLIN) && !accept_client())
                {
                    // error
                }
            }
            else
            {
                if (events[i].events & EPOLLIN)
                {
                    IO_Utils::Packet packet;

                    int res = connections[fd]->recv_packet(packet);
                    if (res != 0)
                    {
                        std::cerr << std::format("Error recv packet with res = {}", res) << std::endl;
                    }
                    else
                    {
                        // nothing, just read packet
                    }
                }

                if (events[i].events & EPOLLRDHUP)
                {
                    if (registrar->deregister_socket(fd) != 0)
                    {
                        // error
                    }

                    connections.erase(fd);
                }
            }
        }
    }
}

bool Server::accept_client()
{
    errno = 0;
    auto new_client_connection = std::make_unique<IO_Utils::TCP_Connection>(*server_connection);
    if (new_client_connection->get_fd() < 0)
    {
        std::cerr << std::format("TCP client accept failure with errno = {}", errno) << std::endl;

        return false;
    }

    errno = 0;
    if (registrar->register_socket(new_client_connection->get_fd(), EPOLLIN | EPOLLRDHUP) < 0)
    {
        std::cerr << std::format("TCP client register failure with errno = {}", errno) << std::endl;

        return false;
    }

    connections[new_client_connection->get_fd()] = std::move(new_client_connection);

    return true;
}

Server::~Server()
{
    // release registrar first (and deregister all connections), before close sockets
    registrar.release();

    connections.clear();
}

Client::Client(IO_Utils::Socket server_address, size_t amount_of_connections, size_t seed) : server_address(server_address), amount_of_connections(amount_of_connections), seed(seed)
{
    errno = 0;
    registrar = std::make_unique<IO_Utils::Registrar>();
    if (registrar->get_epoll_fd() < 0)
    {
        throw std::runtime_error(std::format("Can't create registrar correctly with errno = {}", errno));
    }

    while (connections.size() < amount_of_connections)
    {
        if (!connect_client())
        {
            throw std::runtime_error("TCP client connect error");
        }
    }

    srand(seed);
}

void Client::run(std::atomic<bool> &stop)
{
    epoll_event events[IO_Utils::MAX_EVENTS];

    while (!stop.load())
    {
        while (connections.size() < amount_of_connections && !stop.load())
        {
            if (!connect_client())
            {
                // error
            }
        }

        errno = 0;
        int nfds = epoll_wait(registrar->get_epoll_fd(), events, IO_Utils::MAX_EVENTS, IO_Utils::TIMEOUT);
        if (nfds < 0)
        {
            if (errno = EINTR)
            {
                // Its okay, program was interrupted
            }
            else
            {
                std::cerr << std::format("Epoll_wait error, epoll_fd = {}, errno = {}", registrar->get_epoll_fd(), errno) << std::endl;
            }
        }

        for (int i = 0; i < nfds; ++i)
        {
            int fd = events[i].data.fd;

            if (events[i].events & EPOLLOUT)
            {
                int error;
                socklen_t len = sizeof(error);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
                if (error != 0)
                {
                    std::cerr << std::format("Connection failed for fd = {}, error = {}", fd, error) << "\n";

                    errno = 0;
                    if (registrar->deregister_socket(fd) != 0)
                    {
                        std::cerr << std::format("Can't deregister socket with errno = {}", errno) << std::endl;
                    }

                    connections.erase(fd);

                    continue;
                }

                IO_Utils::Packet packet = generate_packet();

                int res = connections[fd]->send_packet(packet);
                if (res != 0)
                {
                    std::cerr << std::format("Error send packet with result = {}", res) << std::endl;
                }
                else
                {
                    errno = 0;
                    if (shutdown(fd, SHUT_WR) != 0)
                    {
                        std::cerr << std::format("Can't shutdown socket with errno = {}", errno) << std::endl;
                    }

                    errno = 0;
                    if (registrar->deregister_socket(fd) != 0)
                    {
                        std::cerr << std::format("Can't deregister socket with errno = {}", errno) << std::endl;
                    }

                    connections.erase(fd);
                }
            }
        }
    }
}

bool Client::connect_client()
{
    errno = 0;
    auto client_connection = std::make_unique<IO_Utils::TCP_Connection>(server_address, IO_Utils::TCP_Connection_Method::Connect);
    if (client_connection->get_fd() < 0)
    {
        std::cerr << std::format("TCP client connect failure with errno = {}", errno) << std::endl;

        return false;
    }

    errno = 0;
    if (registrar->register_socket(client_connection->get_fd(), EPOLLOUT) < 0)
    {
        std::cerr << std::format("TCP client register failure with errno = {}", errno) << std::endl;

        return false;
    }

    connections[client_connection->get_fd()] = std::move(client_connection);

    return true;
}

IO_Utils::Packet Client::generate_packet()
{
    IO_Utils::Packet packet(server_address);
    std::vector<uint8_t> data;

    // amount of numbers 8bit numbers
    size_t numbers = 1 + rand() / (RAND_MAX / 126);
    for (size_t i = 0; i < numbers; ++i)
    {
        // Fill with randow 8bit number
        data.push_back(rand() / (RAND_MAX / 255));
    }

    packet.set_data(data);

    return packet;
}

Client::~Client()
{
    // release registrar first (and deregister all connections), before close sockets
    registrar.release();

    connections.clear();
}