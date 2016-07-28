#include "WebSocketWrapper.hpp"
#include <string>
#include <iostream>
#include <chrono>

#include "json/json.h"

void print_message(std::string msg) {
  std::cout << msg << "\n";
}

int main(void) {
  WebSocketWrapper ws("ws://localhost:5000/channel/test");

  if (ws.Initialize()) {
    std::cout << "Hello world!\n";
  } else {
    std::cout << "Fuck you world\n";
  }

  ChunkQueue messages;

  std::function<void(std::string)> onMessage = [&messages](std::string msg) {
    messages.push(std::shared_ptr<Chunk>(new Chunk((const void *)msg.c_str(), msg.length())));
  };

  ws.SetOnMessage(onMessage);
  ws.Start();

  Json::Reader reader;
  while (true) {
    ChunkPtr cur_msg = messages.wait_and_pop();
    std::string msg((const char *)cur_msg->Data(), cur_msg->Length());
    std::cout << msg << "\n";
    Json::Value root;
    if (reader.parse(msg, root)) {
      if (root["type"] == "client_connected") {
        std::cout << "Time to get the rtc party started\n";
      }
    } else {
      std::cout << "Parse failed" << "\n";
    }
  }

  ws.Close();

  return 0;
}
