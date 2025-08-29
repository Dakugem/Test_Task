#include "flow.h"

uint64_t Flow::get_mean_ethernet_packet_size() const
{
    return bytes_sended_in_ethernet / amount_of_ethernet_packets;
}

uint64_t Flow::get_mean_data_rate() const
{
    std::chrono::duration<double> elapsed = last_packet_time - start_time;
    auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
    return (elapsed_seconds.count() > 1e-9)? bytes_sended_in_tcp_payload / elapsed_seconds.count() : 0;
}

void Flow::register_packet(size_t eth_packet_size, size_t tcp_payload_size, std::chrono::time_point<std::chrono::steady_clock> timestamp)
{
    amount_of_ethernet_packets++;
    bytes_sended_in_ethernet += eth_packet_size;
    bytes_sended_in_tcp_payload += tcp_payload_size;
    last_packet_time = timestamp;
}

bool Flow::operator==(const Flow &other) const
{
    return flow_tuple == other.flow_tuple;
}

bool Flow_Compare::operator()(const Flow &a, const Flow &b) const
{
    if (a.get_mean_data_rate() == b.get_mean_data_rate())
    {
        auto a_tuple = a.get_flow_tuple();
        auto b_tuple = b.get_flow_tuple();

        if (std::get<0>(a_tuple) == std::get<0>(b_tuple))
        {
            return std::get<1>(a_tuple) < std::get<1>(b_tuple);
        }
        else
        {
            return std::get<0>(a_tuple) < std::get<0>(b_tuple);
        }
    }

    return a.get_mean_data_rate() > b.get_mean_data_rate();
}

namespace std
{
    std::size_t hash<Flow>::operator()(const Flow &flow) const
    {
        std::size_t h1 = std::hash<IO_Utils::Socket>{}(std::get<0>(flow.get_flow_tuple()));
        std::size_t h2 = std::hash<IO_Utils::Socket>{}(std::get<1>(flow.get_flow_tuple()));

        return h1 ^ (h2 << 1);
    }
}