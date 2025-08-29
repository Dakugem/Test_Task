#include "pcap_worker.h"

#include <linux/if_ether.h>
#include <stdexcept>
#include <format>
#include <iostream>

// Need pcap_init called previously
Pcap_Worker::Pcap_Worker(char *name) : name(name)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    p = pcap_open_live(name, 512, 1, 500, errbuf);
    if (p == NULL)
    {
        throw std::runtime_error(std::format("Error occured while pcap_open_live with errbuff {}", errbuf));
    }

    char filter[] = "link proto \\ip and ip proto \\tcp";
    bpf_program filter_program;
    bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;
    if (pcap_compile(p, &filter_program, filter, 0, netmask) || pcap_setfilter(p, &filter_program))
    {
        pcap_close(p);

        throw std::runtime_error(std::format("Error occured while set up filter with errbuf {}", pcap_geterr(p)));
    }
    pcap_freecode(&filter_program);

    dlt = pcap_datalink(p);
    if (dlt != DLT_EN10MB)
    {
        pcap_close(p);

        throw std::runtime_error(std::format("Can't handle that datalink type: {}", pcap_datalink_val_to_name(dlt)));
    }
}

void Pcap_Worker::run(std::atomic<bool> &stop, IO_Utils::Queue<Flow> &queue)
{
    while (!stop.load())
    {
        pcap_pkthdr *header;
        const u_char *data;
        int res = pcap_next_ex(p, &header, &data);

        switch (res)
        {
        case 1:
            handle_packet(header, data, queue);
            break;
        case 0:
            // nothing
            break;
        case PCAP_ERROR:
            std::cerr << "Error while packet capture wirh errbuf " << pcap_geterr(p) << std::endl;
            break;
        case PCAP_ERROR_BREAK:
            // loop break, it's okay
            break;
        default:
            break;
        }

        
    }
}

void Pcap_Worker::handle_packet(pcap_pkthdr *header, const u_char *data, IO_Utils::Queue<Flow> &queue)
{
    size_t ip_header_start = 14;
    size_t ip_addr_offset = ip_header_start + 12; // length of ethernet header + ip_addr_offset of adresses in ipv4 header
    size_t IHL = (data[ip_header_start] & 0x0F) * 4;
    size_t tcp_header_start = ip_header_start + IHL;

    //Too short capture
    if(header->caplen < tcp_header_start + 20) return;

    uint32_t src_ip = (uint32_t)data[ip_addr_offset] << 24 | (uint32_t)data[ip_addr_offset + 1] << 16 | (uint32_t)data[ip_addr_offset + 2] << 8 | (uint32_t)data[ip_addr_offset + 3];
    uint16_t src_port = (uint32_t)data[tcp_header_start] << 8 | (uint32_t)data[tcp_header_start + 1];
    uint32_t dst_ip = (uint32_t)data[ip_addr_offset + 4] << 24 | (uint32_t)data[ip_addr_offset + 4 + 1] << 16 | (uint32_t)data[ip_addr_offset + 4 + 2] << 8 | (uint32_t)data[ip_addr_offset + 4 + 3];
    uint16_t dst_port = (uint32_t)data[tcp_header_start + 2] << 8 | (uint32_t)data[tcp_header_start + 2 + 1];

    //IO_Utils::Socket src_socket(src_ip, ntohs(src_port)), dst_socket(dst_ip, ntohs(dst_port));
    IO_Utils::Socket src_socket(src_ip, src_port), dst_socket(dst_ip, dst_port);

    Flow temp_flow(src_socket, dst_socket);

    if (flows.contains(temp_flow))
    {
        temp_flow = *flows.find(temp_flow);
        flows.erase(temp_flow);
    }

    size_t eth_packet_size, tcp_payload_size, ip_total_length, TCP_header_length;
    std::chrono::time_point<std::chrono::steady_clock> timestamp;

    ip_total_length = (uint32_t)data[ip_header_start + 2] << 8 | (uint32_t)data[ip_header_start + 2 + 1];
    TCP_header_length = ((data[ip_header_start + 2] & 0xF0) >> 4) * 4;

    eth_packet_size = header->len;
    tcp_payload_size = ip_total_length - IHL - TCP_header_length;
    timestamp = std::chrono::steady_clock::now();

    temp_flow.register_packet(eth_packet_size, tcp_payload_size, timestamp);
    flows.insert(temp_flow);

    queue.push(std::make_unique<Flow>(temp_flow));

    //std::cout << "handle packet with src " << src_socket.get_addr_to_str() << " and dst " << dst_socket.get_addr_to_str() << " ether type " << std::endl;
}

void Pcap_Worker::break_loop()
{
    pcap_breakloop(p);
}

Pcap_Worker::~Pcap_Worker()
{
    pcap_close(p);
}