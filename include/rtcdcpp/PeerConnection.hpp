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

#pragma once

#include "ChunkQueue.hpp"
#include "DataChannel.hpp"
#include "RTCCertificate.hpp"
#include "Logging.hpp"
#include <atomic>
#include <map>

namespace rtcdcpp {

class NiceWrapper;
class DTLSWrapper;
class SCTPWrapper;

struct RTCIceServer {
  std::string hostname;
  int port;
};

std::ostream &operator<<(std::ostream &os, const RTCIceServer &ice_server);

struct RTCConfiguration {
  std::vector<RTCIceServer> ice_servers;
  std::pair<unsigned, unsigned> ice_port_range;
  std::string ice_ufrag;
  std::string ice_pwd;
  std::vector<RTCCertificate> certificates;
};

class PeerConnection {
  friend class DTLSWrapper;
 public:
  struct IceCandidate {
    IceCandidate(const std::string &candidate, const std::string &sdpMid, int sdpMLineIndex)
        : candidate(candidate), sdpMid(sdpMid), sdpMLineIndex(sdpMLineIndex) {}
    std::string candidate;
    std::string sdpMid;
    int sdpMLineIndex;
  };

  using IceCandidateCallbackPtr = std::function<void(IceCandidate)>;
  using DataChannelCallbackPtr = std::function<void(std::shared_ptr<DataChannel> channel)>;

  PeerConnection(const RTCConfiguration &config, IceCandidateCallbackPtr icCB, DataChannelCallbackPtr dcCB);

  virtual ~PeerConnection();

  const RTCConfiguration &config() { return config_; }

  /**
   *
   * Parse Offer SDP
   */
  void ParseOffer(std::string offer_sdp);

  /**
   * Generate Offer SDP
   */
  std::string GenerateOffer();

  /**
   * Generate Answer SDP
   */
  std::string GenerateAnswer();

  /**
   * Create Data Channel
   */
  void CreateDataChannel(std::string label, std::string protocol="");

  /**
  * Handle remote ICE Candidate.
  * Supports trickle ice candidates.
  */
  bool SetRemoteIceCandidate(std::string candidate_sdp);

  /**
  * Handle remote ICE Candidates.
  * TODO: Handle trickle ice candidates.
  */
  bool SetRemoteIceCandidates(std::vector<std::string> candidate_sdps);

  /**
   * Create a new data channel with the given label.
   * Only callable once RTCConnectedCallback has been called.
   * TODO: Handle creating data channels before generating SDP, so that the
   *       data channel is created as part of the connection process.
   */
  //    std::shared_ptr<DataChannel> CreateDataChannel(std::string label);

  /**
   * Notify when remote party creates a DataChannel.
   * XXX: This is *not* a callback saying that a call to CreateDataChannel
   *      has succeeded. This is a call saying the remote party wants to
   *      create a new data channel.
   */
  //	void SetDataChannelCreatedCallback(DataChannelCallbackPtr cb);

  // TODO: Error callbacks

  void SendStrMsg(std::string msg, uint16_t sid);
  void SendBinaryMsg(const uint8_t *data, int len, uint16_t sid);

  /* Internal Callback Handlers */
  void OnLocalIceCandidate(std::string &ice_candidate);
  void OnIceReady();
  void OnDTLSHandshakeDone();
  void OnSCTPMsgReceived(ChunkPtr chunk, uint16_t sid, uint32_t ppid);

 private:
  RTCConfiguration config_;
  const IceCandidateCallbackPtr ice_candidate_cb;
  const DataChannelCallbackPtr new_channel_cb;

  std::string mid;

  enum Role { Client, Server } role = Client;

  std::atomic<bool> iceReady{false};
  std::unique_ptr<NiceWrapper> nice;
  std::unique_ptr<DTLSWrapper> dtls;
  std::unique_ptr<SCTPWrapper> sctp;

  std::map<uint16_t, std::shared_ptr<DataChannel>> data_channels;
  std::shared_ptr<DataChannel> GetChannel(uint16_t sid);

  /**
  * Constructor helper
  * Initialize the RTC connection.
  * Allocates all internal structures and configs, and starts ICE gathering.
  */
  bool Initialize();

  // DataChannel message parsing
  void HandleNewDataChannel(ChunkPtr chunk, uint16_t sid);
  void HandleDataChannelAck(uint16_t sid);
  void HandleStringMessage(ChunkPtr chunk, uint16_t sid);
  void HandleBinaryMessage(ChunkPtr chunk, uint16_t sid);

  std::shared_ptr<Logger> logger = GetLogger("rtcdcpp.PeerConnection");

};
}
