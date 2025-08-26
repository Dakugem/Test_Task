#pragma once

#include <cstdint>
#include <unordered_set>

namespace IO_Utils
{
    constexpr int MAX_EVENTS = 32;
    constexpr int TIMEOUT = 1000;

    class Registrar
    {
        int epoll_fd;
        std::unordered_set<int> fds;

    public:
        Registrar();
        ~Registrar();

        int register_socket(int fd, uint32_t events);
        int deregister_socket(int fd);

        int get_epoll_fd();

        Registrar(const Registrar &) = delete;
        Registrar &operator=(const Registrar &) = delete;
    };
}