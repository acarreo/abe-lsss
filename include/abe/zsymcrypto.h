/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
/// 
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
/// 
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
/// 
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
///	\file   zsymcrypto.h
///
///	\brief  Class definition for PKE and ABE thin context wrappers
///
///	\author Alan Dunn and J. Ayo Akinyele
///

#ifndef __ZSYMCRYPTO__
#define __ZSYMCRYPTO__

#include <memory>
#include <string>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "zabe.h"


namespace crypto {


// Implementation of SymmetricKeyHandle
class OpenABESymKeyHandleImpl : public OpenABESymKeyHandle {
public:
  void encrypt(std::string& ciphertext,
               const std::string& plaintext);
  void decrypt(std::string& plaintext,
               const std::string& ciphertext);
  void exportRawKey(std::string& key);
  void exportKey(std::string& key);

  OpenABESymKeyHandleImpl(const std::string& keyBytes,
                      bool apply_b64_encode = false);
  OpenABESymKeyHandleImpl(OpenABEByteString& keyBytes,
                      OpenABEByteString& authData,
                      bool apply_b64_encode = false);
  virtual ~OpenABESymKeyHandleImpl();

protected:
  int security_level_;
  std::string key_;
  bool b64_encode_;
  OpenABEByteString authData_;
};

// Hash-based key derivation function
void OpenABEComputeHKDF(OpenABEByteString& key, OpenABEByteString& salt,
    		            OpenABEByteString& info, size_t key_len,
    		            OpenABEByteString& output_key);
// generate a random symmetric key
void generateSymmetricKey(std::string& key, uint32_t keyLen);
const std::string printAsHex(const std::string& bin_buf);

// Enum for encryption modes
enum class EncryptionMode {
  CBC,
  GCM,
  STREAM_GCM
};

class SymKeyEncHandler : ZObject {
public:
  SymKeyEncHandler();
  SymKeyEncHandler(const std::string& key, EncryptionMode mode = EncryptionMode::GCM, bool apply_b64_encode = false);
  SymKeyEncHandler(const std::shared_ptr<OpenABESymKey>& key, EncryptionMode mode = EncryptionMode::GCM, bool apply_b64_encode = false);

  ~SymKeyEncHandler();
}

  void setAuthData(const OpenABEByteString& authData);
  void setSKEHandler(const std::shared_ptr<OpenABESymKey>& key);
  void setSKEHandler(const std::string& key);

  std::string encrypt(const std::string& plaintext);
  std::string decrypt(const std::string& ciphertext);

private:
  bool b64_encode_;
  OpenABEByteString authData_;
  EncryptionMode encryption_mode_;
  std::shared_ptr<OpenABESymKey> key_;

  // Pointers to different encryption handlers
  std::unique_ptr<OpenABESymKeyEnc> cbc_handler_;
  std::unique_ptr<OpenABESymKeyAuthEnc> gcm_handler_;
};

#endif // __ZSYMCRYPTO__
