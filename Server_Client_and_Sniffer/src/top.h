#pragma once

#include "network_io.h"
#include "queue.h"
#include "flow.h"

#include <tuple>
#include <set>
#include <unordered_set>

class Top
{
    IO_Utils::Queue<Flow>& flow_queue;
    std::unordered_set<Flow> storage;
public: 
    Top(IO_Utils::Queue<Flow>& queue) : flow_queue(queue){};
    void update_data();
    std::vector<Flow> get_n_first_sorted_flows(size_t n = 10);
};