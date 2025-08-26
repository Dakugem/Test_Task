#include "server.h"
#include "client.h"

#include <csignal>
#include <stdlib.h>
#include <stdexcept>
#include <atomic>
#include <string>
#include <iostream>

std::atomic<bool> STOP{false};

void sigint_handler(int signal_number)
{
  std::cout << "Shutdown started..." << std::endl;
  STOP.load(true);
}

int main(int argc, char *argv[])
{
  signal(SIGINT, sigint_handler);
  // server_address Socket
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

  std::unique_ptr<Network_Object> object = nullptr;
  try
  {
    if (mode)
    {
      object = std::make_unique<Server>(server_address);

      std::cout << "Server started" << std::endl;
    }
    else
    {
      object = std::make_unique<Client>(server_address, connections, seed);

      std::cout << "Client started" << std::endl;
    }
  }
  catch (const std::exception& e)
  {
    std::cerr << "Error occured while creating Network_Object: " << e.what << std::endl;
    return -1;
  }

  object->run(STOP);

  std::cout << "Shutdown complete" << std::endl;

  return 0;
}
