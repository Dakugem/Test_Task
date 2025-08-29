#pragma once

#include "flow.h"
#include "top.h"

#include <pcap.h>

#include <atomic>
#include <unordered_set>

class Pcap_Worker{
    int dlt;
    pcap_t* p;
    char* name;
    std::unordered_set<Flow> flows;

    void handle_packet(pcap_pkthdr *header, const u_char *data, IO_Utils::Queue<Flow> &queue);
public:
    Pcap_Worker(char* name);

    void run(std::atomic<bool>& stop, IO_Utils::Queue<Flow>& queue);

    void break_loop();

    ~Pcap_Worker();
};