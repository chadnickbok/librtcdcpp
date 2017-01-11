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
 * RTC Handler.
 */

#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/generator_iterator.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/random.hpp>

#include "PeerConnection.hpp"

#include "DTLSWrapper.hpp"
#include "NiceWrapper.hpp"
#include "SCTPWrapper.hpp"

using namespace std;
using namespace log4cxx;

LoggerPtr PeerConnection::logger(Logger::getLogger("librtcpp.PeerConnection"));

PeerConnection::PeerConnection(std::string stun_server, int stun_port, IceCandidateCallbackPtr icCB, DataChannelCallbackPtr dcCB, string sdp)
    : stun_server(stun_server), stun_port(stun_port), ice_candidate_cb(icCB), new_channel_cb(dcCB) {
  if (!ParseSDP(sdp)) throw runtime_error("Could not parse SDP");
  if (!Initialize()) throw runtime_error("Could not initialise");
}

PeerConnection::~PeerConnection() {
  sctp->Stop();
  dtls->Stop();
  nice->Stop();
}

bool PeerConnection::Initialize() {
  this->nice = make_unique<NiceWrapper>(this, stun_server, stun_port);
  this->dtls = make_unique<DTLSWrapper>(this);
  this->sctp = make_unique<SCTPWrapper>(
      std::bind(&DTLSWrapper::EncryptData, dtls.get(), std::placeholders::_1),
      std::bind(&PeerConnection::OnSCTPMsgReceived, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

  if (remote_username.length() == 0 || remote_password.length() == 0) {
    LOG4CXX_ERROR(logger, "Nice failure: no username or password");
    return false;
  }
  if (!nice->Initialize()) {
    LOG4CXX_ERROR(logger, "Nice failure");
    return false;
  }
  nice->SetRemoteCredentials(remote_username, remote_password);

  LOG4CXX_DEBUG(logger, "RTC: nice initialized");

  if (!dtls->Initialize()) {
    LOG4CXX_ERROR(logger, "DTLS failure");
    return false;
  }
  LOG4CXX_DEBUG(logger, "RTC: dtls initialized");

  if (!sctp->Initialize()) {
    LOG4CXX_ERROR(logger, "sctp failure");
    return false;
  }
  LOG4CXX_DEBUG(logger, "RTC: sctp initialized");

  nice->SetDataReceivedCallback(std::bind(&DTLSWrapper::DecryptData, dtls.get(), std::placeholders::_1));

  dtls->SetDecryptedCallback(std::bind(&SCTPWrapper::DTLSForSCTP, sctp.get(), std::placeholders::_1));

  dtls->SetEncryptedCallback(std::bind(&NiceWrapper::SendData, nice.get(), std::placeholders::_1));

  nice->StartSendLoop();

  return true;
}

bool PeerConnection::ParseSDP(std::string sdp) {
  std::stringstream ss(sdp);
  std::string line;

  while (std::getline(ss, line)) {
    int port = 0;

    if (boost::starts_with(line, "a=sctpmap:")) {
      std::size_t pos = line.find(":") + 1;
      std::size_t len = line.find(" ") - pos;
      std::string port_str = line.substr(pos, len);
      port = boost::lexical_cast<int>(port_str);
      if (port > 0) {
        std::cerr << "Got port: " << port << std::endl;
        this->remote_port = port;
      }
    } else if (boost::starts_with(line, "a=setup:")) {
      std::size_t pos = line.find(":") + 1;
      std::string setup = line.substr(pos);
      if (boost::starts_with(setup, "actpass") || boost::starts_with(setup, "passive")) {
        this->active = true;
      } else {
        this->active = false;
      }
    } else if (boost::starts_with(line, "a=ice-ufrag:")) {
      std::size_t pos = line.find(":") + 1;
      std::size_t end = line.find("\r");
      this->remote_username = line.substr(pos, end - pos);
    } else if (boost::starts_with(line, "a=ice-pwd:")) {
      std::size_t pos = line.find(":") + 1;
      std::size_t end = line.find("\r");
      this->remote_password = line.substr(pos, end - pos);
    } else if (boost::starts_with(line, "a=mid:")) {
      std::size_t pos = line.find(":") + 1;
      std::size_t end = line.find("\r");
      this->mid = line.substr(pos, end - pos);
    }
  }

  if (remote_username.empty() && remote_password.empty()) {
    LOG4CXX_ERROR(logger, "SDP missing username and password");
    return false;
  }

  return true;
}

std::string random_int() {
  std::stringstream result;
  boost::mt19937 rng((uint32_t)std::time(0));
  boost::uniform_int<> zero_to_nine(0, 9);
  boost::variate_generator<boost::mt19937, boost::uniform_int<>> rando(rng, zero_to_nine);
  for (int i = 0; i < 16; i++) {
    result << rando();
  }

  return result.str();
}

std::string PeerConnection::GenerateSDP() {
  LOG4CXX_TRACE(logger, "Generating SDP");
  std::stringstream sdp;

  sdp << "v=0\r\n";
  sdp << "o=- " << random_int() << " 2 IN IP4 127.0.0.1\r\n";  // Session ID
  sdp << "s=-\r\n";
  sdp << "t=0 0\r\n";
  sdp << "a=msid-semantic: WMS\r\n";
  sdp << "m=application 9 DTLS/SCTP 5000\r\n";  // XXX: hardcoded port
  sdp << "c=IN IP4 0.0.0.0\r\n";
  sdp << this->nice->GetSDP();
  sdp << this->dtls->GetFingerprint();
  sdp << "a=ice-options:trickle\r\n";
  sdp << "a=setup:" << (this->active ? "active" : "passive") << "\r\n";
  // sdp << "a=mid:data\r\n";
  sdp << "a=mid:" << this->mid << "\r\n";
  sdp << "a=sctpmap:5000 webrtc-datachannel 1024\r\n";

  return sdp.str();
}

bool PeerConnection::SetRemoteIceCandidate(Json::Value candidate) { return this->nice->SetRemoteIceCandidate(candidate); }

bool PeerConnection::SetRemoteIceCandidates(Json::Value candidates) { return this->nice->SetRemoteIceCandidates(candidates); }

void PeerConnection::OnLocalIceCandidate(std::string &ice_candidate) {
  if (this->ice_candidate_cb) {
    if (ice_candidate.size() > 2) {
      ice_candidate = ice_candidate.substr(2);
    }
    IceCandidate candidate(ice_candidate, this->mid, 0);
    this->ice_candidate_cb(candidate);
  }
}

void PeerConnection::OnIceReady() {
  LOG4CXX_TRACE(logger, "OnIceReady(): Time to ping DTLS");
  if (!iceReady) {
    iceReady = true;
    this->dtls->Start();
  } else {
    // TODO work out
    LOG4CXX_WARN(logger, "OnIceReady(): Called twice!!");
  }
}

void PeerConnection::OnDTLSHandshakeDone() {
  LOG4CXX_TRACE(logger, "OnDTLSHandshakeDone(): Time to get the SCTP party started");
  this->sctp->Start();
}

// Matches DataChannel onmessage
void PeerConnection::OnSCTPMsgReceived(ChunkPtr chunk, uint16_t sid, uint32_t ppid) {
  LOG4CXX_TRACE(logger, "OnSCTPMsgReceived(): Handling an sctp message");
  if (ppid == PPID_CONTROL) {
    LOG4CXX_TRACE(logger, "Control PPID");
    if (chunk->Data()[0] == DC_TYPE_OPEN) {
      LOG4CXX_TRACE(logger, "New channel time!");
      HandleNewDataChannel(chunk, sid);
    } else if (chunk->Data()[0] == DC_TYPE_ACK) {
      LOG4CXX_TRACE(logger, "DC ACK");
      // HandleDataChannelAck(chunk, sid); XXX: Don't care right now
    } else {
      LOG4CXX_TRACE(logger, "Unknown msg_type for ppid control: " << (int)chunk->Data()[0]);
    }
  } else if ((ppid == PPID_STRING) || (ppid == PPID_STRING_EMPTY)) {
    LOG4CXX_TRACE(logger, "String msg");
    HandleStringMessage(chunk, sid);
  } else if ((ppid == PPID_BINARY) || (ppid == PPID_BINARY_EMPTY)) {
    LOG4CXX_TRACE(logger, "Binary msg");
    HandleBinaryMessage(chunk, sid);
  } else {
    LOG4CXX_ERROR(logger, "Unknown ppid=" << ppid);
  }
}

std::shared_ptr<DataChannel> PeerConnection::GetChannel(uint16_t sid) {
  auto iter = data_channels.find(sid);
  if (iter != data_channels.end()) {
    return data_channels[sid];
  }

  return std::shared_ptr<DataChannel>();
}

void PeerConnection::HandleNewDataChannel(ChunkPtr chunk, uint16_t sid) {
  uint8_t *raw_msg = chunk->Data();
  dc_open_msg open_msg;
  open_msg.chan_type = raw_msg[1];
  open_msg.priority = (raw_msg[2] << 8) + raw_msg[3];
  open_msg.reliability = (raw_msg[4] << 24) + (raw_msg[5] << 16) + (raw_msg[6] << 8) + raw_msg[7];
  open_msg.label_len = (raw_msg[8] << 8) + raw_msg[9];
  open_msg.protocol_len = (raw_msg[10] << 8) + raw_msg[11];

  std::string label(reinterpret_cast<char *>(raw_msg + 12), open_msg.label_len);
  std::string protocol(reinterpret_cast<char *>(raw_msg + 12 + open_msg.label_len), open_msg.protocol_len);

  LOG4CXX_DEBUG(logger, "Creating channel with sid: " << sid << ", chan_type: " << (int)open_msg.chan_type << ", label: " << label
                                                      << ", protocol: " << protocol);
  // TODO: Support overriding an existing channel
  auto new_channel = std::make_shared<DataChannel>(this, sid, open_msg.chan_type, label, protocol);

  data_channels[sid] = new_channel;

  if (this->new_channel_cb) {
    this->new_channel_cb(new_channel);
  } else {
    LOG4CXX_WARN(logger, "No new channel callback, ignoring new channel");
  }
}

void PeerConnection::HandleStringMessage(ChunkPtr chunk, uint16_t sid) {
  auto cur_channel = GetChannel(sid);
  if (!cur_channel) {
    LOG4CXX_WARN(logger, "Received msg on unknown channel: " << sid);
    return;
  }

  std::string cur_msg(reinterpret_cast<char *>(chunk->Data()), chunk->Length());

  cur_channel->OnStringMsg(cur_msg);
}

void PeerConnection::HandleBinaryMessage(ChunkPtr chunk, uint16_t sid) {
  auto cur_channel = GetChannel(sid);
  if (!cur_channel) {
    LOG4CXX_WARN(logger, "Received binary msg on unknown channel: " << sid);
    return;
  }

  cur_channel->OnBinaryMsg(chunk);
}

void PeerConnection::SendStrMsg(std::string str_msg, uint16_t sid) {
  auto cur_msg = std::make_shared<Chunk>((const uint8_t *)str_msg.c_str(), str_msg.size());
  this->sctp->GSForSCTP(cur_msg, sid, PPID_STRING);
}

void PeerConnection::SendBinaryMsg(const uint8_t *data, int len, uint16_t sid) {
  auto cur_msg = std::make_shared<Chunk>(data, len);
  this->sctp->GSForSCTP(cur_msg, sid, PPID_BINARY);
}
