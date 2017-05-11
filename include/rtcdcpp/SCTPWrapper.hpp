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

/**
 * Wrapper around usrsctp.
 */

#include "ChunkQueue.hpp"
#include "PeerConnection.hpp"

#include <thread>

#include <usrsctp.h>

namespace rtcdcpp {

#define MAX_OUT_STREAM 256
#define MAX_IN_STREAM 256

class SCTPWrapper {
 public:
  using MsgReceivedCallbackPtr = std::function<void(ChunkPtr chunk, uint16_t sid, uint32_t ppid)>;
  using DTLSEncryptCallbackPtr = std::function<void(ChunkPtr)>;

  SCTPWrapper(DTLSEncryptCallbackPtr dtlsEncryptCB, MsgReceivedCallbackPtr msgReceivedCB);
  virtual ~SCTPWrapper();

  bool Initialize();
  void Start();
  void Stop();
  //  int GetStreamCursor();
  //  void SetStreamCursor(int i);

  // Handle a decrypted SCTP packet
  void DTLSForSCTP(ChunkPtr chunk);
  
  void SendACK();
  void CreateDCForSCTP(std::string label, std::string protocol="");

  dc_open_msg *data;
  uint16_t sid;
  std::string label;
  std::string protocol;

  dc_open_msg* GetDataChannelData();
  uint16_t GetSid();
  std::string GetProtocol();
  std::string GetLabel();
  void SetDataChannelSID(uint16_t sid);

  // Send a message to the remote connection
  // Note, this will cause 1+ DTLSEncrypt callback calls
  void GSForSCTP(ChunkPtr chunk, uint16_t sid, uint32_t ppid);

 private:
  //  PeerConnection *peer_connection;
  bool started{false};
  struct socket *sock;
  uint16_t local_port;
  uint16_t remote_port;
  int stream_cursor;

  bool connectSentData{false};
  std::mutex connectMtx;
  std::condition_variable connectCV;

  bool readyDataChannel{false};
  std::mutex createDCMtx;
  std::condition_variable createDC;

  ChunkQueue send_queue;
  ChunkQueue recv_queue;

  const DTLSEncryptCallbackPtr dtlsEncryptCallback;
  const MsgReceivedCallbackPtr msgReceivedCallback;

  std::atomic<bool> should_stop{false};
  std::thread recv_thread;
  std::thread connect_thread;

  void RunConnect();
  void RecvLoop();

  // SCTP has output a packet ready for DTLS
  int OnSCTPForDTLS(void *data, size_t len, uint8_t tos, uint8_t set_df);

  // SCTP has received a packet for GameSurge
  int OnSCTPForGS(struct socket *sock, union sctp_sockstore addr, void *data, size_t len, struct sctp_rcvinfo recv_info, int flags);

  void OnMsgReceived(const uint8_t *data, size_t len, int ppid, int sid);
  void OnNotification(union sctp_notification *notify, size_t len);

  // usrsctp callbacks
  static int _OnSCTPForDTLS(void *sctp_ptr, void *data, size_t len, uint8_t tos, uint8_t set_df);
  static void _DebugLog(const char *format, ...);
  static int _OnSCTPForGS(struct socket *sock, union sctp_sockstore addr, void *data, size_t len, struct sctp_rcvinfo recv_info, int flags,
                          void *user_data);

  std::shared_ptr<Logger> logger = GetLogger("rtcdcpp.SCTP");
};
}
