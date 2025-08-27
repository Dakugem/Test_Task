#include "registrar.h"

#include <unistd.h>
#include <sys/epoll.h>

namespace IO_Utils
{

    Registrar::Registrar()
    {
        epoll_fd = epoll_create1(0);
    }

    Registrar::~Registrar()
    {
        if (epoll_fd >= 0)
        {
            for (int fd : fds)
            {
                this->deregister_socket(fd);
            }

            if(!fds.empty()) //error

            close(epoll_fd);

            epoll_fd = -1;
        }
    }

    int Registrar::register_socket(int fd, uint32_t events)
    {
        epoll_event _events;
        _events.events = events;
        _events.data.fd = fd;

        int res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &_events);

        if (res == 0)
        {
            fds.insert(fd);
        }

        return res;
    }

    int Registrar::deregister_socket(int fd)
    {
        if (epoll_fd < 0)
            return -1;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1)
        {
            return -2;
        }

        if (fds.erase(fd) < 1)
            return -3;

        return 0;
    }

    int Registrar::get_epoll_fd()
    {
        return epoll_fd;
    };
}