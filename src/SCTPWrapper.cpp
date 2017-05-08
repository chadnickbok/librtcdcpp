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
 * Wrapper around usrsctp/
 */

#include "rtcdcpp/SCTPWrapper.hpp"

#include <iostream>

namespace rtcdcpp {

using namespace std;

SCTPWrapper::SCTPWrapper(DTLSEncryptCallbackPtr dtlsEncryptCB, MsgReceivedCallbackPtr msgReceivedCB)
    : local_port(5000),  // XXX: Hard-coded for now
      remote_port(5000),
      stream_cursor(0),
      dtlsEncryptCallback(dtlsEncryptCB),
      msgReceivedCallback(msgReceivedCB) {}

SCTPWrapper::~SCTPWrapper() {
  Stop();

  int tries = 0;
  while (usrsctp_finish() != 0 && tries < 5) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  }
}

static uint16_t interested_events[] = {SCTP_ASSOC_CHANGE,         SCTP_PEER_ADDR_CHANGE,   SCTP_REMOTE_ERROR,          SCTP_SEND_FAILED,
                                       SCTP_SENDER_DRY_EVENT,     SCTP_SHUTDOWN_EVENT,     SCTP_ADAPTATION_INDICATION, SCTP_PARTIAL_DELIVERY_EVENT,
                                       SCTP_AUTHENTICATION_EVENT, SCTP_STREAM_RESET_EVENT, SCTP_ASSOC_RESET_EVENT,     SCTP_STREAM_CHANGE_EVENT,
                                       SCTP_SEND_FAILED_EVENT};

// TODO: error callbacks
void SCTPWrapper::OnNotification(union sctp_notification *notify, size_t len) {
  if (notify->sn_header.sn_length != (uint32_t)len) {
    logger->error("OnNotification(len={}) invalid length: {}", len, notify->sn_header.sn_length);
    return;
  }

  switch (notify->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_ASSOC_CHANGE)");
      break;
    case SCTP_PEER_ADDR_CHANGE:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_PEER_ADDR_CHANGE)");
      break;
    case SCTP_REMOTE_ERROR:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_REMOTE_ERROR)");
      break;
    case SCTP_SEND_FAILED_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_SEND_FAILED_EVENT)");
      break;
    case SCTP_SHUTDOWN_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_SHUTDOWN_EVENT)");
      break;
    case SCTP_ADAPTATION_INDICATION:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_ADAPTATION_INDICATION)");
      break;
    case SCTP_PARTIAL_DELIVERY_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_PARTIAL_DELIVERY_EVENT)");
      break;
    case SCTP_AUTHENTICATION_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_AUTHENTICATION_EVENT)");
      break;
    case SCTP_SENDER_DRY_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_SENDER_DRY_EVENT)");
      break;
    case SCTP_NOTIFICATIONS_STOPPED_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_NOTIFICATIONS_STOPPED_EVENT)");
      break;
    case SCTP_STREAM_RESET_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_STREAM_RESET_EVENT)");
      break;
    case SCTP_ASSOC_RESET_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_ASSOC_RESET_EVENT)");
      break;
    case SCTP_STREAM_CHANGE_EVENT:
      SPDLOG_TRACE(logger, "OnNotification(type=SCTP_STREAM_CHANGE_EVENT)");
      break;
    default:
      SPDLOG_TRACE(logger, "OnNotification(type={} (unknown))", notify->sn_header.sn_type);
      break;
  }
}

int SCTPWrapper::_OnSCTPForDTLS(void *sctp_ptr, void *data, size_t len, uint8_t tos, uint8_t set_df) {
  if (sctp_ptr) {
    return static_cast<SCTPWrapper *>(sctp_ptr)->OnSCTPForDTLS(data, len, tos, set_df);
  } else {
    return -1;
  }
}

int SCTPWrapper::OnSCTPForDTLS(void *data, size_t len, uint8_t tos, uint8_t set_df) {
  SPDLOG_TRACE(logger, "Data ready. len={}, tos={}, set_df={}", len, tos, set_df);
  this->dtlsEncryptCallback(std::make_shared<Chunk>(data, len));

  {
    unique_lock<mutex> l(connectMtx);
    this->connectSentData = true;
    connectCV.notify_one();
  }

  return 0;  // success
}

void SCTPWrapper::_DebugLog(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  // std::string msg = Util::FormatString(format, ap);
  char msg[1024 * 16];
  vsprintf(msg, format, ap);
  GetLogger("librtcpp.SCTP")->trace("SCTP: msg={}", msg);
  va_end(ap);
}

int SCTPWrapper::_OnSCTPForGS(struct socket *sock, union sctp_sockstore addr, void *data, size_t len, struct sctp_rcvinfo recv_info, int flags,
                              void *user_data) {
  if (user_data) {
    return static_cast<SCTPWrapper *>(user_data)->OnSCTPForGS(sock, addr, data, len, recv_info, flags);
  } else {
    return -1;
  }
}

int SCTPWrapper::OnSCTPForGS(struct socket *sock, union sctp_sockstore addr, void *data, size_t len, struct sctp_rcvinfo recv_info, int flags) {
  if (len == 0) {
    return -1;
  }

  SPDLOG_TRACE(logger, "Data received. stream={}, len={}, SSN={}, TSN={}, PPID={}",
                len,
                recv_info.rcv_sid,
                recv_info.rcv_ssn,
                recv_info.rcv_tsn,
                ntohl(recv_info.rcv_ppid));

  if (flags & MSG_NOTIFICATION) {
    OnNotification((union sctp_notification *)data, len);
  } else {
    std::cout << "Got msg of size: " << len << "\n";
    OnMsgReceived((const uint8_t *)data, len, recv_info.rcv_sid, ntohl(recv_info.rcv_ppid));
  }
  free(data);
  return 0;
}

void SCTPWrapper::OnMsgReceived(const uint8_t *data, size_t len, int ppid, int sid) {
  this->msgReceivedCallback(std::make_shared<Chunk>(data, len), ppid, sid);
}

bool SCTPWrapper::Initialize() {
  usrsctp_init(0, &SCTPWrapper::_OnSCTPForDTLS, &SCTPWrapper::_DebugLog);
  usrsctp_sysctl_set_sctp_ecn_enable(0);
  usrsctp_register_address(this);

  sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, &SCTPWrapper::_OnSCTPForGS, NULL, 0, this);
  if (!sock) {
    logger->error("Could not create usrsctp_socket. errno={}", errno);
    return false;
  }

  struct linger linger_opt;
  linger_opt.l_onoff = 1;
  linger_opt.l_linger = 0;
  if (usrsctp_setsockopt(this->sock, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)) == -1) {
    logger->error("Could not set socket options for SO_LINGER. errno={}", errno);
    return false;
  }

  struct sctp_paddrparams peer_param;
  memset(&peer_param, 0, sizeof(peer_param));
  peer_param.spp_flags = SPP_PMTUD_DISABLE;
  peer_param.spp_pathmtu = 1200;  // XXX: Does this need to match the actual MTU?
  if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &peer_param, sizeof(peer_param)) == -1) {
    logger->error("Could not set socket options for SCTP_PEER_ADDR_PARAMS. errno={}", errno);
    return false;
  }

  struct sctp_assoc_value av;
  av.assoc_id = SCTP_ALL_ASSOC;
  av.assoc_value = 1;
  if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av)) == -1) {
    logger->error("Could not set socket options for SCTP_ENABLE_STREAM_RESET. errno={}", errno);
    return false;
  }

  uint32_t nodelay = 1;
  if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay)) == -1) {
    logger->error("Could not set socket options for SCTP_NODELAY. errno={}", errno);
    return false;
  }

  /* Enable the events of interest */
  struct sctp_event event;
  memset(&event, 0, sizeof(event));
  event.se_assoc_id = SCTP_ALL_ASSOC;
  event.se_on = 1;
  int num_events = sizeof(interested_events) / sizeof(uint16_t);
  for (int i = 0; i < num_events; i++) {
    event.se_type = interested_events[i];
    if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) == -1) {
      logger->error("Could not set socket options for SCTP_EVENT {}. errno={}", i, errno);
      return false;
    }
  }

  struct sctp_initmsg init_msg;
  memset(&init_msg, 0, sizeof(init_msg));
  init_msg.sinit_num_ostreams = MAX_OUT_STREAM;
  init_msg.sinit_max_instreams = MAX_IN_STREAM;
  if (usrsctp_setsockopt(this->sock, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof(init_msg)) == -1) {
    logger->error("Could not set socket options for SCTP_INITMSG. errno={}", errno);
    return false;
  }

  struct sockaddr_conn sconn;
  sconn.sconn_family = AF_CONN;
  sconn.sconn_port = htons(remote_port);
  sconn.sconn_addr = (void *)this;
#ifdef HAVE_SCONN_LEN
  sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif

  if (usrsctp_bind(this->sock, (struct sockaddr *)&sconn, sizeof(sconn)) == -1) {
    logger->error("Could not usrsctp_bind. errno={}", errno);
    return false;
  }

  return true;
}

void SCTPWrapper::Start() {
  if (started) {
    logger->error("Start() - already started!");
    return;
  }

  SPDLOG_TRACE(logger, "Start()");
  started = true;

  this->recv_thread = std::thread(&SCTPWrapper::RecvLoop, this);
  this->connect_thread = std::thread(&SCTPWrapper::RunConnect, this);
}

void SCTPWrapper::Stop() {
  this->should_stop = true;

  send_queue.Stop();
  recv_queue.Stop();

  connectCV.notify_one();  // unblock the recv thread in case we never connected
  if (this->recv_thread.joinable()) {
    this->recv_thread.join();
  }

  if (this->connect_thread.joinable()) {
    this->connect_thread.join();
  }

  if (sock) {
    usrsctp_shutdown(sock, SHUT_RDWR);
    usrsctp_close(sock);
    sock = nullptr;
  }
}

void SCTPWrapper::DTLSForSCTP(ChunkPtr chunk) { this->recv_queue.push(chunk); }

int SCTPWrapper::GetSid(){
    return this->sid;
  }

dc_open_msg* SCTPWrapper::GetDataChannelData(){
  return this->data;
  }

std::string SCTPWrapper::GetLabel(){
  return this->label;
  }
std::string SCTPWrapper::GetProtocol(){
  return this->label;
  }
void SCTPWrapper::SetDataChannelSID(int sid)
  {
    this->sid = sid;
  }

void SCTPWrapper::CreateDCForSCTP(std::string label, std::string protocol) {

  std::unique_lock<std::mutex> l2(createDCMtx);
  while (!this->readyDataChannel) {
    createDC.wait(l2);
  }
  struct sctp_sndinfo sinfo = {0};
  int sid;
  sid = this->sid ;
  sinfo.snd_sid = sid;
  sinfo.snd_ppid = htonl(PPID_CONTROL); 

  int total_size = sizeof *this->data + label.size() + protocol.size() - (2 * sizeof(char *));
  this->data = (dc_open_msg *)calloc(1, total_size);
  this->data->msg_type = DC_TYPE_OPEN;
  this->data->chan_type = DATA_CHANNEL_RELIABLE;
  this->data->priority = htons(0); // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-10#section-6.4
  this->data->reliability = htonl(0);
  this->data->label_len = htons(label.length());
  this->data->protocol_len = htons(protocol.length());
  // try to overwrite last two char* from the struct
  memcpy(&this->data->label, label.c_str(), label.length());
  memcpy(&this->data->label + label.length(), protocol.c_str(), protocol.length());

  this->label = label.c_str();
  this->protocol = protocol.c_str();

  if (started) {
    if (usrsctp_sendv(this->sock, this->data, total_size, NULL, 0, &sinfo, sizeof(sinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
      logger->error("Failed to send a datachannel open request.");
    } else {
      logger->info("Datachannel open request has gone through.");
    }
  }
}
// Send a message to the remote connection
void SCTPWrapper::GSForSCTP(ChunkPtr chunk, uint16_t sid, uint32_t ppid) {
  struct sctp_sendv_spa spa = {0};

  // spa.sendv_flags = SCTP_SEND_SNDINFO_VALID | SCTP_SEND_PRINFO_VALID;
  spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

  spa.sendv_sndinfo.snd_sid = sid;
  // spa.sendv_sndinfo.snd_flags = SCTP_EOR | SCTP_UNORDERED;
  spa.sendv_sndinfo.snd_flags = SCTP_EOR;
  spa.sendv_sndinfo.snd_ppid = htonl(ppid);

  // spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
  // spa.sendv_prinfo.pr_value = 0;

  int tries = 0;
  while (tries < 5) {
    if (usrsctp_sendv(this->sock, chunk->Data(), chunk->Length(), NULL, 0, &spa, sizeof(spa), SCTP_SENDV_SPA, 0) < 0) {
      logger->error("FAILED to send, try: {}", tries);
      tries += 1;
      std::this_thread::sleep_for(std::chrono::seconds(tries));
    } else {
      return;
    }
  }
  //tried about 5 times and still no luck
  throw std::runtime_error("Send failed");
}

void SCTPWrapper::RecvLoop() {
  // Util::SetThreadName("SCTP-RecvLoop");
//  NDC ndc("SCTP-RecvLoop");

  SPDLOG_TRACE(logger, "RunRecv()");

  {
    // We need to wait for the connect thread to send some data
    unique_lock<mutex> l(connectMtx);
    while (!this->connectSentData && !this->should_stop) {
      connectCV.wait_for(l, chrono::milliseconds(100));
    }
  }

  SPDLOG_DEBUG(logger, "RunRecv() sent_data=true");

  while (!this->should_stop) {
    ChunkPtr chunk = this->recv_queue.wait_and_pop();
    if (!chunk) {
      return;
    }
    SPDLOG_DEBUG(logger, "RunRecv() Handling packet of len - {}", chunk->Length());
    usrsctp_conninput(this, chunk->Data(), chunk->Length(), 0);
  }
}

void SCTPWrapper::RunConnect() {
  // Util::SetThreadName("SCTP-Connect");
  SPDLOG_TRACE(logger, "RunConnect() port={}", remote_port);

  struct sockaddr_conn sconn;
  sconn.sconn_family = AF_CONN;
  sconn.sconn_port = htons(remote_port);
  sconn.sconn_addr = (void *)this;
#ifdef HAVE_SCONN_LEN
  sconn.sconn_len = sizeof((void *)this);
#endif

  // Blocks until connection succeeds/fails
  int connect_result = usrsctp_connect(sock, (struct sockaddr *)&sconn, sizeof sconn);

  if ((connect_result < 0) && (errno != EINPROGRESS)) {
    SPDLOG_DEBUG(logger, "Connection failed. errno={}", errno);
    should_stop = true;

    {
      // Unblock the recv thread
      unique_lock<mutex> l(connectMtx);
      connectCV.notify_one();

    }

    // TODO let the world know we failed :(

  } else {
    SPDLOG_DEBUG(logger, "Connected on port {}", remote_port);
    unique_lock<mutex> l2(createDCMtx);
    this->readyDataChannel = true;
    createDC.notify_all();
  }
}
}
