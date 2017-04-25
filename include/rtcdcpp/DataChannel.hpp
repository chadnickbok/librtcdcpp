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
 * WebRTC DataChannel.
*/

#pragma once

#include "Chunk.hpp"

#include <string>

namespace rtcdcpp {

// SCTP PPID Types
#define PPID_CONTROL 50
#define PPID_STRING 51
#define PPID_BINARY 53
#define PPID_STRING_EMPTY 56
#define PPID_BINARY_EMPTY 57

// DataChannel Control Types
#define DC_TYPE_OPEN 0x03
#define DC_TYPE_ACK 0x02

// Channel types
#define DATA_CHANNEL_RELIABLE 0x00
#define DATA_CHANNEL_RELIABLE_UNORDERED 0x80
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT 0x01
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED 0x81
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED 0x02
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED 0x82

typedef struct __attribute__((packed, aligned(1))) {
  uint8_t msg_type;
  uint8_t chan_type;
  uint16_t priority;
  uint32_t reliability;
  uint16_t label_len;
  uint16_t protocol_len;
  char *label;
  char *protocol;
} dc_open_msg;

typedef struct { uint8_t msg_type; } dc_open_ack;

class PeerConnection;

class DataChannel {
  friend class PeerConnection;

 private:
  PeerConnection *pc;
  uint16_t stream_id;
  uint8_t chan_type;
  std::string label;
  std::string protocol;

  // TODO: Priority field

  std::function<void()> open_cb;
  std::function<void(std::string)> str_msg_cb;
  // std::function<void(std::shared_ptr<uint8_t> data, int len)> bin_msg_cb;
  std::function<void(ChunkPtr)> bin_msg_cb;
  std::function<void()> closed_cb;
  std::function<void(std::string description)> error_cb;

  void OnOpen();
  void OnStringMsg(std::string msg);
  void OnBinaryMsg(ChunkPtr msg);
  void OnClosed();
  void OnError(std::string description);

 public:
  DataChannel(PeerConnection *pc, uint16_t stream_id, uint8_t chan_type, std::string label, std::string protocol);
  virtual ~DataChannel();

  /**
   * Get the Stream ID for the DataChannel.
   * XXX: Stream IDs *are* unique.
   */
  uint16_t GetStreamID();

  /**
   * Get the channel type.
   */
  uint8_t GetChannelType();

  /**
   * Get the label for the DataChannel.
   * XXX: Labels are *not* unique.
   */
  std::string GetLabel();

  /**
   * Get the protocol for the DataChannel.
   */
  std::string GetProtocol();

  /**
   * Cleanly close the DataChannel.
   */
  void Close();

  /**
   * Send calls return false if the DataChannel is no longer operational,
   * ie. an error or close event has been detected.
   */
  bool SendString(std::string msg);
  bool SendBinary(const uint8_t *msg, int len);

  // Callbacks

  /**
   * Called when the remote peer 'acks' our data channel
   * This is only called when we were the peer who created the data channel.
   * Receiving this message means its 'safe' to send messages, but messages
   * can be sent before this is received (its just unknown if they'll arrive).
   */
  void SetOnOpen(std::function<void()> open_cb);

  /**
   * Called when we receive a string.
   */
  void SetOnStringMsgCallback(std::function<void(std::string)> recv_str_cb);

  /**
   * Called when we receive a binary blob.
   */
  void SetOnBinaryMsgCallback(std::function<void(ChunkPtr)> msg_binary_cb);

  /**
   * Called when the DataChannel has been cleanly closed.
   * NOT called after the Close() method has been called
   * NOT called after an error has been received.
   */
  void SetOnClosedCallback(std::function<void()> close_cb);

  /**
   * Called when there has been an error in the underlying transport and the
   * data channel is no longer valid.
   */
  void SetOnErrorCallback(std::function<void(std::string description)> error_cb);
};
}
