/**
 * Simple libwebsockets C++ wrapper
 */

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "easywsclient.hpp"

#include <assert.h>
#include <stdio.h>
#include <string>

#include "../../include/ChunkQueue.hpp"

using easywsclient::WebSocket;

class WebSocketWrapper {
 public:
  WebSocketWrapper(std::string url);
  virtual ~WebSocketWrapper();

  bool Initialize();
  void Start();
  void Send(std::string);
  void Close();

  void SetOnMessage(std::function<void(std::string)>);
  void SetOnClose(std::function<void()>);
  void SetOnError(std::function<void(std::string)>);

 private:
  void Loop();

  WebSocket::pointer ws;
  std::string url;
  ChunkQueue send_queue;
  std::function<void(std::string)> onMessage;
  std::thread send_loop;
};
