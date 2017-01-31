/**
 * Copyright (c) 2016, Andrew Gault and Nick Chadwick.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Basic implementation of libnice stuff.
 */

#include <netdb.h>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>

extern "C" {
#include <sys/types.h>
}

#include "rtcdcpp/NiceWrapper.hpp"

void ReplaceAll(std::string &s, const std::string &search, const std::string &replace) {
  size_t pos = 0;
  while ((pos = s.find(search, pos)) != std::string::npos) {
    s.replace(pos, search.length(), replace);
    pos += replace.length();
  }
}

namespace rtcdcpp {

using namespace std;
using namespace log4cxx;

LoggerPtr NiceWrapper::logger(Logger::getLogger("librtcpp.Nice"));

NiceWrapper::NiceWrapper(PeerConnection *peer_connection, std::string stun_server, int stun_port)
    : peer_connection(peer_connection),
      stun_server(stun_server),
      stun_port(stun_port),
      stream_id(0),
      should_stop(false),
      send_queue(),
      agent(NULL, nullptr),
      loop(NULL, nullptr),
      packets_sent(0) {
  data_received_callback = [](ChunkPtr x) { ; };
  if (logger->isDebugEnabled())
    nice_debug_enable(false);
  else
    nice_debug_disable(true);
}

NiceWrapper::~NiceWrapper() { Stop(); }

void new_local_candidate(NiceAgent *agent, NiceCandidate *candidate, gpointer user_data) {
  NiceWrapper *nice = (NiceWrapper *)user_data;
  gchar *cand = nice_agent_generate_local_candidate_sdp(agent, candidate);
  std::string cand_str(cand);
  nice->OnCandidate(cand_str);
  g_free(cand);
}

void NiceWrapper::OnCandidate(std::string candidate) {
  LOG4CXX_DEBUG(logger, "On candidate: " << candidate);
  this->peer_connection->OnLocalIceCandidate(candidate);
}

void candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data) {
  NiceWrapper *nice = (NiceWrapper *)user_data;
  nice->OnGatheringDone();
}

// TODO: Callback for this
void NiceWrapper::OnGatheringDone() {
  LOG4CXX_DEBUG(logger, "ICE: candidate gathering done");
  std::string empty_candidate("");
  this->peer_connection->OnLocalIceCandidate(empty_candidate);
}

// TODO: Callbacks on failure
void component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer user_data) {
  NiceWrapper *nice = (NiceWrapper *)user_data;
  nice->OnStateChange(stream_id, component_id, state);
}

void NiceWrapper::OnStateChange(uint32_t stream_id, uint32_t component_id, uint32_t state) {
  switch (state) {
    case (NICE_COMPONENT_STATE_DISCONNECTED):
      LOG4CXX_TRACE(logger, "ICE: DISCONNECTED");
      break;
    case (NICE_COMPONENT_STATE_GATHERING):
      LOG4CXX_TRACE(logger, "ICE: GATHERING");
      break;
    case (NICE_COMPONENT_STATE_CONNECTING):
      LOG4CXX_TRACE(logger, "ICE: CONNECTING");
      break;
    case (NICE_COMPONENT_STATE_CONNECTED):
      LOG4CXX_TRACE(logger, "ICE: CONNECTED");
      break;
    case (NICE_COMPONENT_STATE_READY):
      LOG4CXX_TRACE(logger, "ICE: READY");
      this->OnIceReady();
      break;
    case (NICE_COMPONENT_STATE_FAILED):
      LOG4CXX_TRACE(logger, "ICE FAILED: " << stream_id << " - " << component_id);
      break;
    default:
      LOG4CXX_TRACE(logger, "ICE: Unknown state: " << state);
      break;
  }
}

// TODO: Turn this into a callback
void NiceWrapper::OnIceReady() { this->peer_connection->OnIceReady(); }

void new_selected_pair(NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *lcandidate, NiceCandidate *rcandidate,
                       gpointer user_data) {
  std::cerr << "ICE: new selected pair" << std::endl;
  NiceWrapper *nice = (NiceWrapper *)user_data;
  nice->OnSelectedPair();
}

void NiceWrapper::OnSelectedPair() { LOG4CXX_TRACE(logger, "OnSelectedPair"); }

void data_received(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data) {
  NiceWrapper *nice = (NiceWrapper *)user_data;
  nice->OnDataReceived((const uint8_t *)buf, len);
}

void NiceWrapper::OnDataReceived(const uint8_t *buf, int len) {
  // std::cerr << "ICE: data received - " << len << std::endl;
  LOG4CXX_TRACE(logger, "Nice data IN: " << len);
  this->data_received_callback(std::make_shared<Chunk>(buf, len));
}

void nice_log_handler(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data) {
  NiceWrapper *nice = (NiceWrapper *)user_data;
  nice->LogMessage(message);
}

void NiceWrapper::LogMessage(const gchar *message) { LOG4CXX_TRACE(logger, "libnice: " << message); }

bool NiceWrapper::Initialize() {
  int log_flags = G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION;
  g_log_set_handler(NULL, (GLogLevelFlags)log_flags, nice_log_handler, this);
  this->loop = std::unique_ptr<GMainLoop, void (*)(GMainLoop *)>(g_main_loop_new(NULL, FALSE), g_main_loop_unref);
  if (!this->loop) {
    LOG4CXX_TRACE(logger, "Failed to initialize GMainLoop");
  }

  this->agent = std::unique_ptr<NiceAgent, decltype(&g_object_unref)>(nice_agent_new(g_main_loop_get_context(loop.get()), NICE_COMPATIBILITY_RFC5245),
                                                                      g_object_unref);
  if (!this->agent) {
    LOG4CXX_TRACE(logger, "Failed to initialize nice agent");
    return false;
  }

  this->g_main_loop_thread = std::thread(g_main_loop_run, this->loop.get());

  g_object_set(G_OBJECT(agent.get()), "upnp", FALSE, NULL);
  g_object_set(G_OBJECT(agent.get()), "controlling-mode", 0, NULL);
  if (!stun_server.empty()) {
    struct hostent *stun_host = gethostbyname(stun_server.c_str());
    if (stun_host == NULL) {
      LOG4CXX_WARN(logger, "Failed to lookup host for server: " << stun_server);
    } else {
      in_addr *address = (in_addr *)stun_host->h_addr;
      const char *ip_address = inet_ntoa(*address);

      g_object_set(G_OBJECT(agent.get()), "stun-server", ip_address, NULL);
    }
  } else {
    LOG4CXX_ERROR(logger, "stun server empty");
  }
  if (stun_port > 0) {
    g_object_set(G_OBJECT(agent.get()), "stun-server-port", stun_port, NULL);
  } else {
    LOG4CXX_ERROR(logger, "stun port empty");
  }

  g_signal_connect(G_OBJECT(agent.get()), "candidate-gathering-done", G_CALLBACK(candidate_gathering_done), this);
  g_signal_connect(G_OBJECT(agent.get()), "component-state-changed", G_CALLBACK(component_state_changed), this);
  g_signal_connect(G_OBJECT(agent.get()), "new-candidate-full", G_CALLBACK(new_local_candidate), this);
  g_signal_connect(G_OBJECT(agent.get()), "new-selected-pair", G_CALLBACK(new_selected_pair), this);

  // TODO: Learn more about nice streams
  this->stream_id = nice_agent_add_stream(agent.get(), 1);
  if (this->stream_id == 0) {
    return false;
  }

  nice_agent_set_stream_name(agent.get(), this->stream_id, "application");
  nice_agent_attach_recv(agent.get(), this->stream_id, 1, g_main_loop_get_context(loop.get()), data_received, this);

  if (!nice_agent_gather_candidates(agent.get(), this->stream_id)) {
    return false;
  }

  return true;
}

void NiceWrapper::StartSendLoop() { this->send_thread = std::thread(&NiceWrapper::SendLoop, this); }

void NiceWrapper::Stop() {
  this->should_stop = true;

  send_queue.Stop();
  if (this->send_thread.joinable()) {
    this->send_thread.join();
  }

  g_main_loop_quit(this->loop.get());

  if (this->g_main_loop_thread.joinable()) {
    this->g_main_loop_thread.join();
  }
}

void NiceWrapper::ParseRemoteSDP(std::string remote_sdp) {
  string crfree_remote_sdp = remote_sdp;

  // TODO: Improve this. This is needed because otherwise libnice will wrongly take the '\r' as part of ice-ufrag/password.
  ReplaceAll(crfree_remote_sdp, "\r\n", "\n");

  int rc = nice_agent_parse_remote_sdp(this->agent.get(), crfree_remote_sdp.c_str());

  if (rc < 0) {
    throw std::runtime_error("ParseRemoteSDP: " + std::string(strerror(rc)));
  } else {
    LOG4CXX_INFO(logger, "ICE: Added " << rc << " Candidates");
  }
}

void NiceWrapper::SendData(ChunkPtr chunk) {
  if (this->stream_id == 0) {
    LOG4CXX_TRACE(logger, "ICE: ERROR sending data to unitialized nice context");
    return;
  }

  this->send_queue.push(chunk);
}

// Pull items off the send queue and call nice_agent_send
void NiceWrapper::SendLoop() {
  while (!this->should_stop) {
    ChunkPtr chunk = send_queue.wait_and_pop();
    if (!chunk) {
      return;
    }
    size_t cur_len = chunk->Length();
    int result = 0;
    // std::cerr << "ICE: Sending data of len " << cur_len << std::endl;
    LOG4CXX_TRACE(logger, "Nice data OUT: " << cur_len);
    result = nice_agent_send(this->agent.get(), this->stream_id, 1, (guint)cur_len, (const char *)chunk->Data());
    if (result != cur_len) {
      LOG4CXX_TRACE(logger, "ICE: Failed to send data of len - " << cur_len);
      LOG4CXX_TRACE(logger, "ICE: Failed send result - " << result);
    } else {
      // std::cerr << "ICE: Data sent " << cur_len << std::endl;
    }
  }
}

std::string NiceWrapper::GenerateLocalSDP() {
  std::stringstream nice_sdp;
  std::stringstream result;
  std::string line;

  gchar *raw_sdp = nice_agent_generate_local_sdp(agent.get());
  nice_sdp << raw_sdp;

  while (std::getline(nice_sdp, line)) {
    if (g_str_has_prefix(line.c_str(), "a=ice-ufrag:") || g_str_has_prefix(line.c_str(), "a=ice-pwd:")) {
      result << line << "\r\n";
    }
  }

  return result.str();
}

bool NiceWrapper::SetRemoteIceCandidate(string candidate_sdp) {
  GSList *list = NULL;
  NiceCandidate *rcand = nice_agent_parse_remote_candidate_sdp(this->agent.get(), this->stream_id, candidate_sdp.c_str());

  if (rcand == NULL) {
    LOG4CXX_TRACE(logger, "failed to parse remote candidate");
    return false;
  }
  list = g_slist_append(list, rcand);

  bool success = (nice_agent_set_remote_candidates(this->agent.get(), this->stream_id, 1, list) > 0);

  g_slist_free_full(list, (GDestroyNotify)&nice_candidate_free);

  return success;
}

bool NiceWrapper::SetRemoteIceCandidates(vector <string> candidate_sdps) {
  GSList *list = NULL;
  for (auto candidate_sdp : candidate_sdps) {
    NiceCandidate *rcand = nice_agent_parse_remote_candidate_sdp(this->agent.get(), this->stream_id, candidate_sdp.c_str());

    if (rcand == NULL) {
      LOG4CXX_TRACE(logger, "failed to parse remote candidate");
      return false;
    }
    list = g_slist_append(list, rcand);
  }

  bool success = (nice_agent_set_remote_candidates(this->agent.get(), this->stream_id, 1, list) > 0);

  g_slist_free_full(list, (GDestroyNotify)&nice_candidate_free);

  return success;
}

void NiceWrapper::SetDataReceivedCallback(std::function<void(ChunkPtr)> data_received_callback) {
  this->data_received_callback = data_received_callback;
}
}
