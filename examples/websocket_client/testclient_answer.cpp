/**
 * Simple WebRTC test client.
 */

#include "WebSocketWrapper.hpp"
#include "json/json.h"

#include <rtcdcpp/PeerConnection.hpp>
#include <rtcdcpp/Logging.hpp>

#include <iostream>

using namespace rtcdcpp;

int main(void) {
#ifndef SPDLOG_DISABLED
  auto console_sink = std::make_shared<spdlog::sinks::ansicolor_sink>(spdlog::sinks::stdout_sink_mt::instance());
  spdlog::create("rtcdcpp.PeerConnection", console_sink);
  spdlog::create("rtcdcpp.SCTP", console_sink);
  spdlog::create("rtcdcpp.Nice", console_sink);
  spdlog::create("rtcdcpp.DTLS", console_sink);
  spdlog::set_level(spdlog::level::debug);
#endif

  WebSocketWrapper ws("ws://localhost:5000/channel/test");
  std::shared_ptr<PeerConnection> pc;
  std::shared_ptr<DataChannel> dc;

  if (!ws.Initialize()) {
    std::cout << "WebSocket connection failed\n";
    return 0;
  }

  RTCConfiguration config;
  config.ice_servers.emplace_back(RTCIceServer{"stun3.l.google.com", 19302});

  bool running = true;

  ChunkQueue messages;

  std::function<void(std::string)> onMessage = [&messages](std::string msg) {
    messages.push(std::shared_ptr<Chunk>(new Chunk((const void *)msg.c_str(), msg.length())));
  };

  std::function<void(PeerConnection::IceCandidate)> onLocalIceCandidate = [&ws](PeerConnection::IceCandidate candidate) {
    Json::Value jsonCandidate;
    jsonCandidate["type"] = "candidate";
    jsonCandidate["msg"]["candidate"] = candidate.candidate;
    jsonCandidate["msg"]["sdpMid"] = candidate.sdpMid;
    jsonCandidate["msg"]["sdpMLineIndex"] = candidate.sdpMLineIndex;

    Json::StreamWriterBuilder wBuilder;
    ws.Send(Json::writeString(wBuilder, jsonCandidate));
  };

  std::function<void(std::shared_ptr<DataChannel> channel)> onDataChannel = [&dc](std::shared_ptr<DataChannel> channel) {
    std::cout << "Hey cool, got a data channel\n";
    dc = channel;
    dc->SendString("Hello from native code");
    //dc->Close();
  };

  ws.SetOnMessage(onMessage);
  ws.Start();
  ws.Send("{\"type\": \"client_connected\", \"msg\": {}}");

  Json::Reader reader;
  Json::StreamWriterBuilder msgBuilder;

  while (running) {
    ChunkPtr cur_msg = messages.wait_and_pop();
    std::string msg((const char *)cur_msg->Data(), cur_msg->Length());
    std::cout << msg << "\n";
    Json::Value root;
    if (reader.parse(msg, root)) {
      std::cout << "Got msg of type: " << root["type"] << "\n";
      if (root["type"] == "offer") {
        std::cout << "Time to get the rtc party started\n";
        pc = std::make_shared<PeerConnection>(config, onLocalIceCandidate, onDataChannel);

        pc->ParseOffer(root["msg"]["sdp"].asString());
        Json::Value answer;
        answer["type"] = "answer";
        answer["msg"]["sdp"] = pc->GenerateAnswer();
        answer["msg"]["type"] = "answer";

        std::cout << "Sending Answer: " << answer << "\n";
        ws.Send(Json::writeString(msgBuilder, answer));
      } else if (root["type"] == "candidate") {
        pc->SetRemoteIceCandidate("a=" + root["msg"]["candidate"].asString());
      }
    } else {
      std::cout << "Json parse failed"
                << "\n";
    }
  }

  ws.Close();

  return 0;
}
