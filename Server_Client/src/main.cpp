#include "node.h"

#include <signal.h>
#include <stdlib.h>
#include <stdexcept>
#include <atomic>
#include <string>
#include <cstring>
#include <iostream>
#include <memory>

std::atomic<bool> STOP{false};

void sigint_handler(int signal_number)
{
  std::cout << "Shutdown started..." << std::endl;
  STOP.store(true);
}

int main(int argc, char *argv[])
{
  if(signal(SIGINT, sigint_handler) == SIG_ERR){
    std::cerr << "Error while handler create" << std::endl;
    return -1;
  }
  
  IO_Utils::Socket server_address;
  bool mode = false; // True - server, false - client
  // For client only
  size_t connections = 0;
  size_t seed = 0;

  for (int i = 0; i < argc; ++i)
  {
    if (!strcmp(argv[i], "--addr") && argc > i + 1)
    {
      i++;
      if (!server_address.set_addr_from_str(argv[i]))
      {
        std::cerr << "Invalid server address" << std::endl;
        return -1;
      }
    }

    if (!strcmp(argv[i], "--mode") && argc > i + 1)
    {
      i++;

      if (!strcmp(argv[i], "server") && argc > i + 1)
      {
        mode = true;
      }
      else if (!strcmp(argv[i], "client") && argc > i + 1)
      {
        mode = false;
      }
      else
      {
        std::cerr << "Invalid operating mode" << std::endl;
        return -1;
      }
    }

    if (!strcmp(argv[i], "--connections") && argc > i + 1)
    {
      i++;

      // Могут быть ошибки с аргументом argv[i]
      connections = std::stoull(argv[i]);
    }

    if (!strcmp(argv[i], "--seed") && argc > i + 1)
    {
      i++;

      // Могут быть ошибки с аргументом argv[i]
      seed = std::stoull(argv[i]);
    }
  }

  std::unique_ptr<Node> node;
  try
  {
    if (mode)
    {
      node = std::make_unique<Server>(server_address);

      std::cout << "Server started" << std::endl;
    }
    else
    {
      node = std::make_unique<Client>(server_address, connections, seed);

      std::cout << "Client started" << std::endl;
    }
  }
  catch (const std::exception& e)
  {
    std::cerr << "Error occured while creating Network_node: " << e.what() << std::endl;
    return -1;
  }

  node->run(STOP);

  std::cout << "Shutdown complete" << std::endl;

  return 0;
}
