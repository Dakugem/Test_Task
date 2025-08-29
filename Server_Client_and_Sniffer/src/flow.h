#pragma once

#include "network_io.h"

#include <chrono>
#include <tuple>
#include <functional>

class Flow
{
    std::tuple<IO_Utils::Socket, IO_Utils::Socket> flow_tuple; // First socket is src_socket, second - dst_socket

    // 64 bits allows to store enough data
    uint64_t bytes_sended_in_tcp_payload;
    uint64_t bytes_sended_in_ethernet; // Sum of length of all ethernet packets with headers
    uint64_t amount_of_ethernet_packets;

    std::chrono::time_point<std::chrono::steady_clock> start_time;
    std::chrono::time_point<std::chrono::steady_clock> last_packet_time;

public:
    Flow(IO_Utils::Socket src_socket, IO_Utils::Socket dst_socket) : flow_tuple(std::make_tuple(src_socket, dst_socket)),
                                                                     bytes_sended_in_tcp_payload(0),
                                                                     bytes_sended_in_ethernet(0),
                                                                     amount_of_ethernet_packets(0),
                                                                     start_time(std::chrono::steady_clock::now()),
                                                                     last_packet_time(std::chrono::steady_clock::now())
    {
    }

    std::tuple<IO_Utils::Socket, IO_Utils::Socket> get_flow_tuple() const { return flow_tuple; }
    uint64_t get_mean_ethernet_packet_size() const;
    uint64_t get_bytes_sended_in_tcp_payload() const { return bytes_sended_in_tcp_payload; }
    uint64_t get_mean_data_rate() const;

    void register_packet(size_t eth_packet_size, size_t tcp_payload_size, std::chrono::time_point<std::chrono::steady_clock> timestamp);

    bool operator==(const Flow &other) const;
};

class Flow_Compare
{
public:
    bool operator()(const Flow &a, const Flow &b) const;
};

namespace std
{
    template <>
    struct hash<Flow>
    {
        //  The hash function only takes sockets into account, which allows separating the stream from its parameters.
        std::size_t operator()(const Flow &flow) const;
    };
}