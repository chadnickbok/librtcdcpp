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

#pragma once

#include <mutex>
#include <deque>
#include <thread>
#include <memory>
#include <functional>
#include <vector>

#include "json/json.h"

#include "ChunkQueue.hpp"
#include "DataChannel.hpp"

#include "log4cxx/Logger.h"

class NiceWrapper;
class DTLSWrapper;
class SCTPWrapper;
class PubNubWrapper;

class PeerConnection
{
public:

	struct IceCandidate {
		IceCandidate(const std::string& candidate, const std::string& sdpMid, int sdpMLineIndex)
			:candidate(candidate), sdpMid(sdpMid), sdpMLineIndex(sdpMLineIndex) {}
		std::string candidate;
		std::string sdpMid;
		int sdpMLineIndex;
	};

	using IceCandidateCallbackPtr = std::function<void(IceCandidate)>;
	using DataChannelCallbackPtr = std::function<void(std::shared_ptr<DataChannel> channel)>;

	PeerConnection(
		std::string stun_server,
		int stun_port,
		IceCandidateCallbackPtr icCB,
		DataChannelCallbackPtr dcCB,
		std::string sdp);
	virtual ~PeerConnection();

	/**
	 * Generate a local SDP (answer)
	 */
	std::string GenerateSDP();

	/**
	* Handle remote ICE Candidate.
	* Supports trickle ice candidates.
	*/
	bool SetRemoteIceCandidate(Json::Value candidate);

	/**
	* Handle remote ICE Candidates.
	* TODO: Handle trickle ice candidates.
	*/
	bool SetRemoteIceCandidates(Json::Value candidates);

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
	void OnLocalIceCandidate(std::string& ice_candidate);
	void OnIceReady();
	void OnDTLSHandshakeDone();
	void OnSCTPMsgReceived(ChunkPtr chunk, uint16_t sid, uint32_t ppid);

private:

	const std::string stun_server;
	const int stun_port;
	const IceCandidateCallbackPtr ice_candidate_cb;
	const DataChannelCallbackPtr new_channel_cb;

	// SCTP Port Settings, set in ParseSDP()
	// XXX: Not sure if this is actually needed
	int remote_port;
	bool active; // Do we initiate the connection?
	std::string remote_username;
	std::string remote_password;
	std::string mid;

	std::atomic<bool>			 iceReady{ false };
    std::unique_ptr<NiceWrapper> nice;
    std::unique_ptr<DTLSWrapper> dtls;
    std::unique_ptr<SCTPWrapper> sctp;

    std::map<uint16_t, std::shared_ptr<DataChannel>> data_channels;
    std::shared_ptr<DataChannel> GetChannel(uint16_t sid);

	// Constructor helper. Parses the given SDP
	bool ParseSDP(std::string sdp);

	/**
	* Constructor helper
	* Initialize the RTC connection.
	* Allocates all internal structures and configs, and starts ICE gathering.
	* MUST call ParseSDP first
	*/
	bool Initialize();

    // DataChannel message parsing
    void HandleNewDataChannel(ChunkPtr chunk, uint16_t sid);
    void HandleStringMessage(ChunkPtr chunk, uint16_t sid);
    void HandleBinaryMessage(ChunkPtr chunk, uint16_t sid);

	static log4cxx::LoggerPtr logger;
};
