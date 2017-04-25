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
 * Simple wrapper around OpenSSL DTLS.
 */

#include "rtcdcpp/DTLSWrapper.hpp"
#include "rtcdcpp/RTCCertificate.hpp"

#include <iostream>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>

namespace rtcdcpp {

using namespace std;

DTLSWrapper::DTLSWrapper(PeerConnection *peer_connection)
    : peer_connection(peer_connection), certificate_(nullptr), handshake_complete(false), should_stop(false) {
  if (peer_connection->config().certificates.size() != 1) {
    throw std::runtime_error("At least one and only one certificate has to be set");
  }
  certificate_ = &peer_connection->config().certificates.front();
  this->decrypted_callback = [](ChunkPtr x) { ; };
  this->encrypted_callback = [](ChunkPtr x) { ; };
}

DTLSWrapper::~DTLSWrapper() {
  Stop();

  // NOTE: We intentionally do NOT free the BIO's manually

  if (ssl) {
    if (SSL_shutdown(ssl) == 0) {
      SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    ssl = nullptr;
  }
  if (ctx) {
    SSL_CTX_free(ctx);
    ctx = nullptr;
  }
}

static int verify_peer_certificate(int ok, X509_STORE_CTX *ctx) {
  // XXX: This function should ask the user if they trust the cert
  return 1;
}

bool DTLSWrapper::Initialize() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  ctx = SSL_CTX_new(DTLSv1_method());
  if (!ctx) {
    return false;
  }

  if (SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") != 1) {
    return false;
  }

  SSL_CTX_set_read_ahead(ctx, 1);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_peer_certificate);
  SSL_CTX_use_PrivateKey(ctx, certificate_->evp_pkey());
  SSL_CTX_use_certificate(ctx, certificate_->x509());

  if (SSL_CTX_check_private_key(ctx) != 1) {
    return false;
  }

  ssl = SSL_new(ctx);
  if (!ssl) {
    return false;
  }

  in_bio = BIO_new(BIO_s_mem());
  if (!in_bio) {
    return false;
  }
  BIO_set_mem_eof_return(in_bio, -1);

  out_bio = BIO_new(BIO_s_mem());
  if (!out_bio) {
    return false;
  }
  BIO_set_mem_eof_return(out_bio, -1);

  SSL_set_bio(ssl, in_bio, out_bio);

  std::shared_ptr<EC_KEY> ecdh = std::shared_ptr<EC_KEY>(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
  SSL_set_options(ssl, SSL_OP_SINGLE_ECDH_USE);
  SSL_set_tmp_ecdh(ssl, ecdh.get());

  return true;
}

void DTLSWrapper::Start() {
  SPDLOG_TRACE(logger, "Start(): Starting handshake - {}", std::this_thread::get_id());

  if (peer_connection->role != peer_connection->Server) {
  printf("\n ROLE: SERVER");
  SSL_set_accept_state(ssl); // This is for role server.
  } else {
  printf("\n ROLE: CLIENT");
  SSL_set_connect_state(ssl);
  }
  uint8_t buf[4192];
  SSL_do_handshake(ssl);
  while (BIO_ctrl_pending(out_bio) > 0) {
    // XXX: This is not actually valid (buf + offset send after)
    int nbytes = BIO_read(out_bio, buf, sizeof(buf));
    if (nbytes > 0) {
      SPDLOG_TRACE(logger, "Start(): Sending handshake bytes {}", nbytes);
      this->encrypted_callback(std::make_shared<Chunk>(buf, nbytes));
    }
  }

  // std::cerr << "DTLS: handshake started, start encrypt/decrypt threads" << std::endl;
  this->encrypt_thread = std::thread(&DTLSWrapper::RunEncrypt, this);
  this->decrypt_thread = std::thread(&DTLSWrapper::RunDecrypt, this);
}

void DTLSWrapper::Stop() {
  this->should_stop = true;

  encrypt_queue.Stop();
  if (this->encrypt_thread.joinable()) {
    this->encrypt_thread.join();
  }

  decrypt_queue.Stop();
  if (this->decrypt_thread.joinable()) {
    this->decrypt_thread.join();
  }
}

void DTLSWrapper::SetEncryptedCallback(std::function<void(ChunkPtr chunk)> encrypted_callback) { this->encrypted_callback = encrypted_callback; }

void DTLSWrapper::SetDecryptedCallback(std::function<void(ChunkPtr chunk)> decrypted_callback) { this->decrypted_callback = decrypted_callback; }

void DTLSWrapper::DecryptData(ChunkPtr chunk) { this->decrypt_queue.push(chunk); }

void DTLSWrapper::RunDecrypt() {
  SPDLOG_TRACE(logger, "RunDecrypt()");

  bool should_notify = false;
  while (!should_stop) {
    int read_bytes = 0;
    uint8_t buf[2048] = {0};
    ChunkPtr chunk = this->decrypt_queue.wait_and_pop();
    if (!chunk) {
      return;
    }
    size_t cur_len = chunk->Length();

    {
      std::lock_guard<std::mutex> lock(this->ssl_mutex);

      // std::cout << "DTLS: Decrypting data of size - " << chunk->Length() << std::endl;
      BIO_write(in_bio, chunk->Data(), (int)chunk->Length());
      read_bytes = SSL_read(ssl, buf, sizeof(buf));

      if (!handshake_complete) {
        if (BIO_ctrl_pending(out_bio)) {
          uint8_t out_buf[2048];
          int send_bytes = 0;
          while (BIO_ctrl_pending(out_bio) > 0) {
            send_bytes += BIO_read(out_bio, out_buf + send_bytes, sizeof(out_buf) - send_bytes);
          }
          if (send_bytes > 0) {
            this->encrypted_callback(std::make_shared<Chunk>(out_buf, send_bytes));
          }
        }

        if (SSL_is_init_finished(ssl)) {
          handshake_complete = true;
          should_notify = true;
        }
      }
    }

    // std::cerr << "Read this many bytes " << read_bytes << std::endl;
    if (read_bytes > 0) {
      // std::cerr << "DTLS: Calling decrypted callback with data of size: " << read_bytes << std::endl;
      this->decrypted_callback(std::make_shared<Chunk>(buf, read_bytes));
    } else {
      // TODO: SSL error checking
    }

    if (should_notify) {
      // std::cerr << "DTLS: handshake is done" << std::endl;
      should_notify = false;
      peer_connection->OnDTLSHandshakeDone();
    }
  }
}

void DTLSWrapper::EncryptData(ChunkPtr chunk) { this->encrypt_queue.push(chunk); }

void DTLSWrapper::RunEncrypt() {
  SPDLOG_TRACE(logger, "RunEncrypt()");
  while (!this->should_stop) {
    ChunkPtr chunk = this->encrypt_queue.wait_and_pop();
    if (!chunk) {
      return;
    }

    // std::cerr << "DTLS: Encrypting message of len - " << chunk->Length() << std::endl;
    {
      std::lock_guard<std::mutex> lock(this->ssl_mutex);
      uint8_t buf[2048] = {0};
      if (SSL_write(ssl, chunk->Data(), (int)chunk->Length()) != chunk->Length()) {
        // TODO: Error handling
      }

      int nbytes = 0;
      while (BIO_ctrl_pending(out_bio) > 0) {
        nbytes += BIO_read(out_bio, buf + nbytes, 2048 - nbytes);
      }

      if (nbytes > 0) {
        // std::cerr << "DTLS: Calling the encrypted data cb" << std::endl;
        this->encrypted_callback(std::make_shared<Chunk>(buf, nbytes));
      }
    }
  }
}
}
