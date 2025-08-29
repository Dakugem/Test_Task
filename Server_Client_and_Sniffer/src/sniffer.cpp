#include "pcap_worker.h"
#include "top.h"
#include "queue.h"

#include <cstdlib>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <format>
#include <signal.h>

std::atomic<bool> STOP{false};

void sigint_handler(int signal_number)
{
    std::cout << "Shutdown started..." << std::endl;
    STOP.store(true);
}

void draw_top(std::vector<Flow> flows)
{
    std::cout << std::format("Top packet flows:\n");

    for (size_t i = 1; Flow flow : flows)
    {
        std::cout << std::format("{:>2}) {:21}Source socket = {}, destination socket = {}, mean data rate = {}\n",
                                 i,
                                 "",
                                 std::get<0>(flow.get_flow_tuple()).get_addr_to_str(),
                                 std::get<1>(flow.get_flow_tuple()).get_addr_to_str(),
                                 flow.get_mean_data_rate());

        i++;
    }

    std::cout << std::endl;
}

int main()
{
    if (signal(SIGINT, sigint_handler) == SIG_ERR)
    {
        std::cerr << "Error while handler create" << std::endl;
        return -1;
    }

    IO_Utils::Queue<Flow> queue{10000};
    Top top{queue};

    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuff))
    {
        std::cerr << "Pcap_init error with " << errbuff << std::endl;

        return -1;
    }

    pcap_if_t *alldevs, *alldevs_iter;
    if (pcap_findalldevs(&alldevs, errbuff))
    {
        std::cerr << "Pcap_findalldevs error with " << errbuff << std::endl;
    }

    alldevs_iter = alldevs;

    std::vector<char *> if_names;
    std::cout << "List of interfaces" << std::endl;
    size_t i = 1;
    while (alldevs_iter != nullptr)
    {
        if_names.push_back(alldevs_iter->name);

        std::cout << i << ") |" << alldevs_iter->name << "|" << std::endl;

        alldevs_iter = alldevs_iter->next;
        i++;
    }

    size_t if_num = 0;
    while (if_num < 1 || if_num > if_names.size())
    {
        std::cout << "Choose one of it and type it's number: " << std::endl;
        std::cin >> if_num;
    }

    char *if_name = if_names[if_num - 1];

    std::unique_ptr<Pcap_Worker> pcap_worker;
    try
    {
        pcap_worker = std::make_unique<Pcap_Worker>(if_name);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;

        return -1;
    }
    std::thread pcap_worker_thread(&Pcap_Worker::run, std::ref(*pcap_worker), std::ref(STOP), std::ref(queue));

    std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
    while (!STOP.load())
    {
        std::chrono::time_point<std::chrono::steady_clock> curr = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = curr - start;
        auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
        if (elapsed_seconds.count() >= 1)
        {
            system("clear");
            top.update_data();
            draw_top(top.get_n_first_sorted_flows());

            start = curr;
        }
    }

    pcap_worker->break_loop();
    pcap_worker_thread.join();

    pcap_freealldevs(alldevs);

    std::cout << "Shutdown complete" << std::endl;

    return 0;
}