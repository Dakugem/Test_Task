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
  if (signal(SIGINT, sigint_handler) == SIG_ERR)
  {
    std::cerr << "Error while handler create" << std::endl;
    return -1;
  }

  bool isAddress = false, isMode = false, isConnections = false, isSeed = false;
  IO_Utils::Socket server_address;
  bool mode = false; // True - server, false - client
  // For client only
  size_t amount_of_connections = 0;
  size_t seed = 0;

  for (int i = 0; i < argc; ++i)
  {
    if (!strcmp(argv[i], "--addr"))
    {
      if (argc <= i + 1)
      {
        std::cerr << "Server address is empty" << std::endl;
        return -1;
      }

      i++;
      if (!server_address.set_addr_from_str(argv[i]))
      {
        std::cerr << "Invalid server address" << std::endl;
        return -1;
      }

      isAddress = true;
    }

    if (!strcmp(argv[i], "--mode"))
    {
      if (argc <= i + 1)
      {
        std::cerr << "Mode is empty" << std::endl;
        return -1;
      }

      i++;

      if (!strcmp(argv[i], "server") || !strcmp(argv[i], "Server"))
      {
        mode = true;
      }
      else if (!strcmp(argv[i], "client") || !strcmp(argv[i], "Client"))
      {
        mode = false;
      }
      else
      {
        std::cerr << "Invalid operating mode" << std::endl;
        return -1;
      }

      isMode = true;
    }

    if (!strcmp(argv[i], "--connections"))
    {
      if (argc <= i + 1)
      {
        std::cerr << "Connections is empty" << std::endl;
        return -1;
      }

      i++;

      // Могут быть ошибки с аргументом argv[i]
      amount_of_connections = std::stoull(argv[i]);

      isConnections = true;
    }

    if (!strcmp(argv[i], "--seed"))
    {
      if (argc <= i + 1)
      {
        std::cerr << "Seed is empty" << std::endl;
        return -1;
      }

      i++;

      // Могут быть ошибки с аргументом argv[i]
      seed = std::stoull(argv[i]);

      isSeed = true;
    }
  }

  if (!isAddress || !isMode)
  {
    std::cerr << "Empty address or mode" << std::endl;

    return -1;
  }

  if (!mode)
  {
    if (!isConnections || !isSeed)
    {
      std::cerr << "Empty connections or seed" << std::endl;

      return -1;
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
      node = std::make_unique<Client>(server_address, amount_of_connections, seed);

      std::cout << "Client started" << std::endl;
    }
  }
  catch (const std::exception &e)
  {
    std::cerr << "Error occured while creating Network_node: " << e.what() << std::endl;
    return -1;
  }
  
  node->run(STOP);

  std::cout << "Shutdown complete" << std::endl;

  return 0;
}
