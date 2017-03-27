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

#include <cstddef>
#include <cstdint>
#include <memory>

#include <cstring>
#include <condition_variable>
namespace rtcdcpp {

// Utility class for passing messages around
class Chunk {
 private:
  size_t len{0};
  uint8_t *data{nullptr};

 public:
  // TODO memory pool?
  // XXX should we just use a vector?

  // Makes a copy of data
  Chunk(const void *dataToCopy, size_t dataLen) : len(dataLen), data(new uint8_t[len]) { memcpy(data, dataToCopy, dataLen); }

  // Copy constructor
  Chunk(const Chunk &other) : len(other.len), data(new uint8_t[len]) { memcpy(data, other.data, other.len); }

  // Assignment operator
  Chunk &operator=(const Chunk &other) {
    if (data) {
      len = 0;
      delete[] data;
    }
    len = other.len;
    data = new uint8_t[len];
    memcpy(data, other.data, other.len);
    return *this;
  }

  ~Chunk() { delete[] data; }

  size_t Size() const { return len; }
  size_t Length() const { return Size(); }
  uint8_t *Data() const { return data; }
};

using ChunkPtr = std::shared_ptr<Chunk>;
}
