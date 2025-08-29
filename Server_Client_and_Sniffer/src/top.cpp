#include "top.h"

void Top::update_data(){
    auto flow_ptr = flow_queue.pop();
    while(flow_ptr != nullptr){
        Flow flow = *flow_ptr;

        if(storage.contains(flow)){
            storage.erase(flow);
            
        }

        storage.insert(flow);

        flow_ptr = flow_queue.pop();
    }
}

std::vector<Flow> Top::get_n_first_sorted_flows(size_t n){
    std::vector<Flow> result;
    std::set<Flow, Flow_Compare> sorted_storage(storage.begin(), storage.end());

    for(size_t i = 0; Flow flow : sorted_storage){
        if(i >= n) break;
        result.push_back(flow);
        i++;
    }

    return result;
}