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
 * Simple blocking thread-safe queue.
 */

#pragma once

#include "Chunk.hpp"

#include <mutex>
#include <queue>

namespace rtcdcpp {

/**
 * Thread-Safe Queue of DataChunks
 */
class ChunkQueue {
 private:
  mutable std::mutex mut;
  std::queue<ChunkPtr> chunk_queue;
  std::condition_variable data_cond;
  bool stopping;

 public:
  ChunkQueue() : chunk_queue(), stopping(false) {}

  void Stop() {
    std::lock_guard<std::mutex> lock(mut);
    stopping = true;
    data_cond.notify_all();
  }

  void push(ChunkPtr chunk) {
    std::lock_guard<std::mutex> lock(mut);
    if (stopping) {
      return;
    }
    chunk_queue.push(chunk);
    data_cond.notify_one();
  }

  ChunkPtr wait_and_pop() {
    std::unique_lock<std::mutex> lock(mut);
    while (!stopping && chunk_queue.empty()) {
      data_cond.wait(lock);
    }

    if (stopping) {
      return ChunkPtr();
    }

    ChunkPtr res = chunk_queue.front();
    chunk_queue.pop();
    return res;
  }

  bool empty() const {
    std::lock_guard<std::mutex> lock(mut);
    return chunk_queue.empty();
  }
};
}
