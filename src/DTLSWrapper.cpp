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

/**
 * Simple wrapper around OpenSSL DTLS.
 */

#include <iostream>

#include "DTLSWrapper.hpp"

using namespace std;
using namespace log4cxx;

LoggerPtr DTLSWrapper::logger(Logger::getLogger("librtcpp.DTLS"));

DTLSWrapper::DTLSWrapper(PeerConnection *peer_connection)
  : peer_connection(peer_connection), handshake_complete(false), should_stop(false)
{
    memset(this->fingerprint, 0, SHA256_FINGERPRINT_SIZE);
    this->decrypted_callback = [] (ChunkPtr x) { ; };
    this->encrypted_callback = [] (ChunkPtr x) { ; };
}

DTLSWrapper::~DTLSWrapper()
{
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

static int verify_peer_certificate(int ok, X509_STORE_CTX *ctx)
{
    // XXX: This function should ask the user if they trust the cert
    return 1;
}

bool DTLSWrapper::gen_key()
{
    this->key = std::shared_ptr<EVP_PKEY>(EVP_PKEY_new(), EVP_PKEY_free);
    RSA *rsa = RSA_new();

    std::shared_ptr<BIGNUM> exponent(BN_new(), BN_free);

    if (!this->key || !rsa || !exponent) {
        return false;
    }

    if (!BN_set_word(exponent.get(), 0x10001) ||
        !RSA_generate_key_ex(rsa, 1024, exponent.get(), NULL) ||
        !EVP_PKEY_assign_RSA(this->key.get(), rsa)) {
        return false;
    }

    return true;
}

static std::shared_ptr<X509> gen_cert(
        std::shared_ptr<EVP_PKEY> pkey, const char *common, int days)
{
    std::shared_ptr<X509> null_result;

    std::shared_ptr<X509> x509(X509_new(), X509_free);
    std::shared_ptr<BIGNUM> serial_number(BN_new(), BN_free);
    std::shared_ptr<X509_NAME> name(X509_NAME_new(), X509_NAME_free);

    if (!x509 || !serial_number || !name) {
        return null_result;
    }

    if (!X509_set_pubkey(x509.get(), pkey.get())) {
        return null_result;
    }

    if (!BN_pseudo_rand(serial_number.get(), 64, 0, 0)) {
        return null_result;
    }

    ASN1_INTEGER *asn1_serial_number = X509_get_serialNumber(x509.get());
    if (!asn1_serial_number) {
        return null_result;
    }

    if (!BN_to_ASN1_INTEGER(serial_number.get(), asn1_serial_number)) {
        return null_result;
    }

    if (!X509_set_version(x509.get(), 0L)) {
        return null_result;
    }

    if (!X509_NAME_add_entry_by_NID(name.get(), NID_commonName, MBSTRING_UTF8,
            (unsigned char*) common, -1, -1, 0)) {
        return null_result;
    }

    if (!X509_set_subject_name(x509.get(), name.get()) ||
            !X509_set_issuer_name(x509.get(), name.get())) {
        return null_result;
    }

    if (!X509_gmtime_adj(X509_get_notBefore(x509.get()), 0) ||
            !X509_gmtime_adj(X509_get_notAfter(x509.get()), days * 24 * 3600))
    {
        return null_result;
    }

    if (!X509_sign(x509.get(), pkey.get(), EVP_sha1()))
    {
        return null_result;
    }

    return x509;
}

bool DTLSWrapper::Initialize()
{
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
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            verify_peer_certificate);

    if (!gen_key()) {
        return false;
    }
    SSL_CTX_use_PrivateKey(ctx, key.get());

    std::shared_ptr<X509> cert = gen_cert(key, "rtcdcpp", 365);
    if (!cert) {
        return false;
    }
    SSL_CTX_use_certificate(ctx, cert.get());

    if (SSL_CTX_check_private_key(ctx) != 1) {
        return false;
    }

    unsigned int len;
    unsigned char buf[4096] = { 0 };
    if (!X509_digest(cert.get(), EVP_sha256(), buf, &len)) {
        return false;
    }

    if (len > SHA256_FINGERPRINT_SIZE) {
		LOG4CXX_ERROR(logger, "Initialize(): fingerprint size too large for buffer!");
    }

    int offset = 0;
    for (unsigned int i = 0; i < len; ++i) {
        snprintf(fingerprint + offset, 4, "%02X:", buf[i]);
        offset += 3;
    }
    fingerprint[offset - 1] = '\0';

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

    std::shared_ptr<EC_KEY> ecdh = std::shared_ptr<EC_KEY>(
            EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
    SSL_set_options(ssl, SSL_OP_SINGLE_ECDH_USE);
    SSL_set_tmp_ecdh(ssl, ecdh.get());

    return true;
}

void DTLSWrapper::Start()
{
	LOG4CXX_TRACE(logger, "Start(): Starting handshake - " << std::this_thread::get_id());

    // XXX: We can never be the server (sdp always returns active, not passive)
    SSL_set_connect_state(ssl);
    uint8_t buf[4192];
    SSL_do_handshake(ssl);
    while (BIO_ctrl_pending(out_bio) > 0) {
        // XXX: This is not actually valid (buf + offset send after)
        int nbytes = BIO_read(out_bio, buf, sizeof(buf));
        if (nbytes > 0) {
			LOG4CXX_TRACE(logger, "Start(): Sending handshake bytes " << nbytes);
            this->encrypted_callback(std::make_shared<Chunk>(buf, nbytes));
        }
    }

    // std::cerr << "DTLS: handshake started, start encrypt/decrypt threads" << std::endl;
    this->encrypt_thread = std::thread(&DTLSWrapper::RunEncrypt, this);
    this->decrypt_thread = std::thread(&DTLSWrapper::RunDecrypt, this);
}

void DTLSWrapper::Stop()
{
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

std::string DTLSWrapper::GetFingerprint()
{
    return "a=fingerprint:sha-256 " + std::string(this->fingerprint) + "\r\n";
}

void DTLSWrapper::SetEncryptedCallback(
        std::function<void(ChunkPtr chunk)> encrypted_callback)
{
    this->encrypted_callback = encrypted_callback;
}

void DTLSWrapper::SetDecryptedCallback(
      std::function<void(ChunkPtr chunk)> decrypted_callback)
{
    this->decrypted_callback = decrypted_callback;
}

void DTLSWrapper::DecryptData(ChunkPtr chunk)
{
    this->decrypt_queue.push(chunk);
}

void DTLSWrapper::RunDecrypt()
{
	LOG4CXX_TRACE(logger, "RunDecrypt()");

    bool should_notify = false;
    while (!should_stop)
    {
        int read_bytes = 0;
        uint8_t buf[2048] = { 0 };
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

            if (!handshake_complete)
            {
                if (BIO_ctrl_pending(out_bio))
                {
                    uint8_t out_buf[2048];
                    int send_bytes = 0;
                    while (BIO_ctrl_pending(out_bio) > 0)
                    {
                        send_bytes += BIO_read(out_bio, out_buf + send_bytes, sizeof(out_buf) - send_bytes);
                    }
                    if (send_bytes > 0) {
                        this->encrypted_callback(std::make_shared<Chunk>(out_buf, send_bytes));
                    }
                }

                if (SSL_is_init_finished(ssl))
                {
                    handshake_complete = true;
                    should_notify = true;
                }
            }
        }

        // std::cerr << "Read this many bytes " << read_bytes << std::endl;
        if (read_bytes > 0) {
            // std::cerr << "DTLS: Calling decrypted callback with data of size: " << read_bytes << std::endl;
            this->decrypted_callback(std::make_shared<Chunk>(buf, read_bytes));
        }
        else
        {
            // TODO: SSL error checking
        }

        if (should_notify) {
            // std::cerr << "DTLS: handshake is done" << std::endl;
            should_notify = false;
            peer_connection->OnDTLSHandshakeDone();
        }
    }
}

void DTLSWrapper::EncryptData(ChunkPtr chunk)
{
    this->encrypt_queue.push(chunk);
}

void DTLSWrapper::RunEncrypt()
{
	LOG4CXX_TRACE(logger, "RunEncrypt()");
    while (!this->should_stop)
    {
        ChunkPtr chunk = this->encrypt_queue.wait_and_pop();
		if (!chunk) {
			return;
		}

        // std::cerr << "DTLS: Encrypting message of len - " << chunk->Length() << std::endl;
        {
            std::lock_guard<std::mutex> lock(this->ssl_mutex);
            uint8_t buf[2048] = { 0 };
            if (SSL_write(ssl, chunk->Data(), (int)chunk->Length()) != chunk->Length())
            {
                // TODO: Error handling
            }

            int nbytes = 0;
            while (BIO_ctrl_pending(out_bio) > 0)
            {
                nbytes += BIO_read(out_bio, buf + nbytes, 2048 - nbytes);
            }

            if (nbytes > 0)
            {
                // std::cerr << "DTLS: Calling the encrypted data cb" << std::endl;
                this->encrypted_callback(std::make_shared<Chunk>(buf, nbytes));
            }
        }
    }
}
