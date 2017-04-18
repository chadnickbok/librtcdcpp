#include "WebSocketWrapper.hpp"
#include <thread>
#include <iostream>

using namespace rtcdcpp;

WebSocketWrapper::WebSocketWrapper(std::string url) : url(url), send_queue() { ; }

WebSocketWrapper::~WebSocketWrapper() { delete this->ws; }

bool WebSocketWrapper::Initialize() {
  this->ws = WebSocket::from_url(this->url);
  return this->ws ? true : false;
}

void WebSocketWrapper::SetOnMessage(std::function<void(std::string)> onMessage) { this->onMessage = onMessage; }

void WebSocketWrapper::Start() { 
  this->stopping = false;
  this->send_loop = std::thread(&WebSocketWrapper::Loop, this); 
}

void WebSocketWrapper::Loop() {
  while (!this->stopping) {
    this->ws->poll();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (!this->send_queue.empty()) {
      ChunkPtr chunk = this->send_queue.wait_and_pop();
      std::string msg(reinterpret_cast<char const*>(chunk->Data()), chunk->Length());
      this->ws->send(msg);
      this->ws->poll();
    }
    this->ws->dispatch(this->onMessage);
  }
}

void WebSocketWrapper::Send(std::string msg) { this->send_queue.push(std::shared_ptr<Chunk>(new Chunk((const void*)msg.c_str(), msg.length()))); }

void WebSocketWrapper::Close() { this->stopping = true; this->send_loop.join(); }
