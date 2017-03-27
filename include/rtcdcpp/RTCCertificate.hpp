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
 * Wrapper around OpenSSL Certs.
 */

#include <openssl/x509.h>
#include <memory>
#include <cstring>
#include <string>

namespace rtcdcpp {

#define SHA256_FINGERPRINT_SIZE (95 + 1)

class RTCCertificate {
 public:
  static RTCCertificate GenerateCertificate(std::string common_name, int days);

  RTCCertificate(std::string cert_pem, std::string pkey_pem);

  const std::string &fingerprint() const { return fingerprint_; }

 protected:
  friend class DTLSWrapper;

  X509 *x509() const { return x509_.get(); }
  EVP_PKEY *evp_pkey() const { return evp_pkey_.get(); }

 private:
  RTCCertificate(std::shared_ptr<X509> x509, std::shared_ptr<EVP_PKEY> evp_pkey);

  std::shared_ptr<X509> x509_;
  std::shared_ptr<EVP_PKEY> evp_pkey_;
  std::string fingerprint_;
};
}
