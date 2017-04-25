/**
 * Copyright (c) 2017, Andrew Gault, Nick Chadwick and Guillaume Egles.
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

#include "rtcdcpp/PeerConnection.hpp"
#include "rtcdcpp/DTLSWrapper.hpp"
#include "rtcdcpp/NiceWrapper.hpp"
#include "rtcdcpp/SCTPWrapper.hpp"

#include <sstream>

#define SESSION_ID_SIZE 16

namespace rtcdcpp {

using namespace std;

std::ostream &operator<<(std::ostream &os, const RTCIceServer &ice_server) { return os << ice_server.hostname << ":" << ice_server.port; }

PeerConnection::PeerConnection(const RTCConfiguration &config, IceCandidateCallbackPtr icCB, DataChannelCallbackPtr dcCB)
    : config_(config), ice_candidate_cb(icCB), new_channel_cb(dcCB) {
  if (config_.certificates.empty()) {
    config_.certificates.push_back(RTCCertificate::GenerateCertificate("rtcdcpp", 365));
  }
  if (!Initialize()) {
    throw runtime_error("Could not initialize");
  }
}

PeerConnection::~PeerConnection() {
  sctp->Stop();
  dtls->Stop();
  nice->Stop();
}

bool PeerConnection::Initialize() {
  this->nice = make_unique<NiceWrapper>(this);
  this->dtls = make_unique<DTLSWrapper>(this);
  this->sctp = make_unique<SCTPWrapper>(
      std::bind(&DTLSWrapper::EncryptData, dtls.get(), std::placeholders::_1),
      std::bind(&PeerConnection::OnSCTPMsgReceived, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

  if (!dtls->Initialize()) {
    logger->error("DTLS failure");
    return false;
  }
  SPDLOG_DEBUG(logger, "RTC: dtls initialized");

  if (!nice->Initialize()) {
    logger->error("Nice failure");
    return false;
  }
  SPDLOG_DEBUG(logger, "RTC: nice initialized");

  if (!sctp->Initialize()) {
    logger->error("sctp failure");
    return false;
  }
  SPDLOG_DEBUG(logger, "RTC: sctp initialized");

  nice->SetDataReceivedCallback(std::bind(&DTLSWrapper::DecryptData, dtls.get(), std::placeholders::_1));
  dtls->SetDecryptedCallback(std::bind(&SCTPWrapper::DTLSForSCTP, sctp.get(), std::placeholders::_1));
  dtls->SetEncryptedCallback(std::bind(&NiceWrapper::SendData, nice.get(), std::placeholders::_1));
  nice->StartSendLoop();
  return true;
}

void PeerConnection::ParseOffer(std::string offer_sdp) {
  std::stringstream ss(offer_sdp);
  std::string line;

  while (std::getline(ss, line)) {
    if (g_str_has_prefix(line.c_str(), "a=setup:")) {
      std::size_t pos = line.find(":") + 1;
      std::string setup = line.substr(pos);
      if (setup == "active" && this->role == Client) {
        this->role = Server;
      } else if (setup == "passive" && this->role == Server) {
        this->role = Client;
      } else {  // actpass
        // nothing to do
      }
    } else if (g_str_has_prefix(line.c_str(), "a=mid:")) {
      std::size_t pos = line.find(":") + 1;
      std::size_t end = line.find("\r");
      this->mid = line.substr(pos, end - pos);
    }
  }
  nice->ParseRemoteSDP(offer_sdp);
}

std::string random_session_id() {
  const static char *numbers = "0123456789";
  srand((unsigned)time(nullptr));
  std::stringstream result;

  for (int i = 0; i < SESSION_ID_SIZE; ++i) {
    int r = rand() % 10;
    result << numbers[r];
  }
  return result.str();
}
std::string PeerConnection::GenerateOffer() {
  std::stringstream sdp;
  std::string session_id = random_session_id();
  SPDLOG_TRACE(logger, "Generating Answer SDP: session_id={}", session_id);

  sdp << "v=0\r\n";
  sdp << "o=- " << session_id << " 0 IN IP4 0.0.0.0\r\n";  // Session ID
  sdp << "s=-\r\n";
  sdp << "t=0 0\r\n";
  sdp << "a=ice-options:trickle\r\n";
  sdp << "m=application 54609 DTLS/SCTP 5000\r\n";  // XXX: hardcoded port
  sdp << "a=msid-semantic: WMS\r\n";
  sdp << "c=IN IP4 0.0.0.0\r\n";
  //  sdp << "a=mid:data\r\n";
  sdp << "a=sendrecv\r\n";
  // sdp << "a=sctp-port:5000\r\n";
  // sdp << "a=max-message-size:100000\r\n";
  sdp << "a=setup:actpass\r\n";
  sdp << "a=dtls-id:1\r\n";
  sdp << this->nice->GenerateLocalSDP();
  sdp << "a=fingerprint:sha-256 " << dtls->certificate()->fingerprint() << "\r\n";
  sdp << "a=sctpmap:5000 webrtc-datachannel 262144\r\n";

  return sdp.str();
  }
std::string PeerConnection::GenerateAnswer() {
  std::stringstream sdp;
  std::string session_id = random_session_id();
  SPDLOG_TRACE(logger, "Generating Answer SDP: session_id={}", session_id);

  sdp << "v=0\r\n";
  sdp << "o=- " << session_id << " 2 IN IP4 0.0.0.0\r\n";  // Session ID
  sdp << "s=-\r\n";
  sdp << "t=0 0\r\n";
  sdp << "a=msid-semantic: WMS\r\n";
  sdp << "m=application 9 DTLS/SCTP 5000\r\n";  // XXX: hardcoded port
  sdp << "c=IN IP4 0.0.0.0\r\n";
  sdp << this->nice->GenerateLocalSDP();
  sdp << "a=fingerprint:sha-256 " << dtls->certificate()->fingerprint() << "\r\n";
  sdp << "a=ice-options:trickle\r\n";
  sdp << "a=setup:" << (this->role == Client ? "active" : "passive") << "\r\n";
  sdp << "a=mid:" << this->mid << "\r\n";
  sdp << "a=sctpmap:5000 webrtc-datachannel 1024\r\n";

  return sdp.str();
}

bool PeerConnection::SetRemoteIceCandidate(string candidate_sdp) { return this->nice->SetRemoteIceCandidate(candidate_sdp); }

bool PeerConnection::SetRemoteIceCandidates(vector<string> candidate_sdps) { return this->nice->SetRemoteIceCandidates(candidate_sdps); }

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
  SPDLOG_TRACE(logger, "OnIceReady(): Time to ping DTLS");
  if (!iceReady) {
    iceReady = true;
    this->dtls->Start();
  } else {
    // TODO work out
    logger->warn("OnIceReady(): Called twice!!");
  }
}

void PeerConnection::OnDTLSHandshakeDone() {
  SPDLOG_TRACE(logger, "OnDTLSHandshakeDone(): Time to get the SCTP party started");
  this->sctp->Start();
}

// Matches DataChannel onmessage
void PeerConnection::OnSCTPMsgReceived(ChunkPtr chunk, uint16_t sid, uint32_t ppid) {
  SPDLOG_TRACE(logger, "OnSCTPMsgReceived(): Handling an sctp message");
  if (ppid == PPID_CONTROL) {
    SPDLOG_TRACE(logger, "Control PPID");
    if (chunk->Data()[0] == DC_TYPE_OPEN) {
      SPDLOG_TRACE(logger, "New channel time!");
      HandleNewDataChannel(chunk, sid);
    } else if (chunk->Data()[0] == DC_TYPE_ACK) {
      SPDLOG_TRACE(logger, "DC ACK");
      HandleDataChannelAck();
    } else {
      SPDLOG_TRACE(logger, "Unknown msg_type for ppid control: {}", chunk->Data()[0]);
    }
  } else if ((ppid == PPID_STRING) || (ppid == PPID_STRING_EMPTY)) {
    SPDLOG_TRACE(logger, "String msg");
    HandleStringMessage(chunk, sid);
  } else if ((ppid == PPID_BINARY) || (ppid == PPID_BINARY_EMPTY)) {

    SPDLOG_TRACE(logger, "Binary msg");
    HandleBinaryMessage(chunk, sid);
  } else {
    logger->error("Unknown ppid={}", ppid);
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

  SPDLOG_DEBUG(logger, "Creating channel with sid: {}, chan_type: {}, label: {}, protocol: {}", sid, open_msg.chan_type, label, protocol);

  // TODO: Support overriding an existing channel
  auto new_channel = std::make_shared<DataChannel>(this, sid, open_msg.chan_type, label, protocol);

  data_channels[sid] = new_channel;

  if (this->new_channel_cb) {
    this->new_channel_cb(new_channel);
  } else {
    logger->warn("No new channel callback, ignoring new channel");
  }
}

  void PeerConnection::HandleDataChannelAck() {
  dc_open_msg* datachannel_data =   this->sctp->GetDataChannelData();
  int sid =   this->sctp->GetSid();
  std::string label = this->sctp->GetLabel();
  std::string protocol = this->sctp->GetProtocol();  
  // TODO: Support overriding an existing channel
  auto new_channel = std::make_shared<DataChannel>(this, sid, datachannel_data->chan_type, label, protocol);

  data_channels[sid] = new_channel;

  if (this->new_channel_cb) {
    this->new_channel_cb(new_channel);
  } else {
    logger->warn("No new channel callback, ignoring new channel");
  }
}  

void PeerConnection::HandleStringMessage(ChunkPtr chunk, uint16_t sid) {
  auto cur_channel = GetChannel(sid);
  if (!cur_channel) {
    logger->warn("Received msg on unknown channel: {}", sid);
    return;
  }
  std::string cur_msg(reinterpret_cast<char *>(chunk->Data()), chunk->Length());

  cur_channel->OnStringMsg(cur_msg);
}

void PeerConnection::HandleBinaryMessage(ChunkPtr chunk, uint16_t sid) {
  auto cur_channel = GetChannel(sid);
  if (!cur_channel) {
    logger->warn("Received binary msg on unknown channel: {}", sid);
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

void PeerConnection::CreateDataChannel(std::string label, std::string protocol) {
  int sid;
  if(this->role == 0){
    sid = 0;
  }else{
    sid = 1;
  }
  for(int i = sid; i < data_channels.size(); i = i + 2){
    auto iter = data_channels.find(i);
    if (iter == data_channels.end()) {
      sid = i;
      break;
    }
  }
  this->sctp->SetDataChannelSID(sid);
  this->sctp->CreateDCForSCTP(label, protocol);
}
}
