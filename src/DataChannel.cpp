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
 * DataChannel.
 */

#include <iostream>

#include "rtcdcpp/DataChannel.hpp"
#include "rtcdcpp/PeerConnection.hpp"

namespace rtcdcpp {

DataChannel::DataChannel(PeerConnection *pc, uint16_t stream_id, uint8_t chan_type, std::string label, std::string protocol)
    : pc(pc), stream_id(stream_id), chan_type(chan_type), label(label), protocol(protocol) {
  // XXX: Default-noop callbacks
  open_cb = []() { ; };  // XXX: I love and hate that this is valid c++
  str_msg_cb = [](std::string x) { ; };
  bin_msg_cb = [](ChunkPtr data) { ; };
  closed_cb = []() { ; };
  error_cb = [](std::string x) { ; };
}

DataChannel::~DataChannel() { DataChannel::Close(); }

uint16_t DataChannel::GetStreamID() { return this->stream_id; }

uint8_t DataChannel::GetChannelType() { return this->chan_type; }

std::string DataChannel::GetLabel() { return this->label; }

std::string DataChannel::GetProtocol() { return this->protocol; }

/**
 * Close the DataChannel.
 */
void DataChannel::Close() { 
  this->pc->ResetSCTPStream(GetStreamID());
}

bool DataChannel::SendString(std::string msg) {
  std::cerr << "DC: Sending string: " << msg << std::endl;
  this->pc->SendStrMsg(msg, this->stream_id);
  return true;
}

// TODO Take a shared_ptr to datachunk
bool DataChannel::SendBinary(const uint8_t *msg, int len) {
  std::cerr << "DC: Sending binary of len - " << len << std::endl;
  this->pc->SendBinaryMsg(msg, len, this->stream_id);
  std::cerr << "DC: Binary sent" << std::endl;
  return true;
}

void DataChannel::SetOnOpen(std::function<void()> open_cb) { this->open_cb = open_cb; }

void DataChannel::SetOnStringMsgCallback(std::function<void(std::string msg)> str_msg_cb) { this->str_msg_cb = str_msg_cb; }

void DataChannel::SetOnBinaryMsgCallback(std::function<void(ChunkPtr)> bin_msg_cb) { this->bin_msg_cb = bin_msg_cb; }

void DataChannel::SetOnClosedCallback(std::function<void()> closed_cb) { this->closed_cb = closed_cb; }

void DataChannel::SetOnErrorCallback(std::function<void(std::string description)> error_cb) { this->error_cb = error_cb; }

void DataChannel::OnOpen() {
  if (this->open_cb) {
    this->open_cb();
  }
}

void DataChannel::OnStringMsg(std::string msg) {
  if (this->str_msg_cb) {
    this->str_msg_cb(msg);
  }
}

void DataChannel::OnBinaryMsg(ChunkPtr msg) {
  if (this->bin_msg_cb) {
    this->bin_msg_cb(msg);
  }
}

void DataChannel::OnClosed() {
  if (this->closed_cb) {
    this->closed_cb();
  }
}

void DataChannel::OnError(std::string description) {
  if (this->error_cb) {
    this->error_cb(description);
  }
}
}
