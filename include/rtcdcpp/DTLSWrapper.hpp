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

/**
 * Wrapper around OpenSSL DTLS.
 */

#include <cstdint>
#include <functional>
#include <memory>

#include <openssl/rand.h>
#undef X509_NAME
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include "log4cxx/logger.h"

#include "ChunkQueue.hpp"
#include "PeerConnection.hpp"

namespace rtcdcpp {

#define SHA256_FINGERPRINT_SIZE (95 + 1)

class DTLSWrapper {
 public:
  DTLSWrapper(PeerConnection *peer_connection);
  virtual ~DTLSWrapper();

  // Needed to build RTC SDP
  std::string GetFingerprint();

  bool Initialize();
  void Start();
  void Stop();

  void EncryptData(ChunkPtr chunk);
  void DecryptData(ChunkPtr chunk);

  void SetEncryptedCallback(std::function<void(ChunkPtr chunk)>);
  void SetDecryptedCallback(std::function<void(ChunkPtr chunk)>);

 private:
  PeerConnection *peer_connection;

  std::atomic<bool> should_stop;

  ChunkQueue encrypt_queue;
  ChunkQueue decrypt_queue;

  std::thread encrypt_thread;
  std::thread decrypt_thread;

  void RunEncrypt();
  void RunDecrypt();

  // SSL Context
  std::mutex ssl_mutex;
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *in_bio, *out_bio;

  char fingerprint[SHA256_FINGERPRINT_SIZE];

  bool gen_key();
  std::shared_ptr<EVP_PKEY> key;
  bool handshake_complete;

  std::function<void(ChunkPtr chunk)> decrypted_callback;
  std::function<void(ChunkPtr chunk)> encrypted_callback;

  static log4cxx::LoggerPtr logger;
};

}
