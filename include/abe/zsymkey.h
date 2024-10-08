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
/// \file   zsymkey.h
///
/// \brief  Class definition for storing and manipulating
///         the symmetric enc OpenABE keys and ciphertexts.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZSYMKEY_H__
#define __ZSYMKEY_H__

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "zabe.h"
#include "zkey.h"


///
/// Macro definitions
///
#define IV_STR	"IV"
#define CT_STR	"Ciphertext"
#define TG_STR	"Tag"

///
/// @class  OpenABESymKey
///
/// @brief  Class for storing and manipulating symmetric encryption keys.
///

class OpenABESymKey : public OpenABEKey {
protected:
  OpenABEByteString m_keyData;
    
public:
  // Constructors/destructors
  OpenABESymKey() : OpenABEKey() {};
  OpenABESymKey(const std::string ID, OpenABEByteString *uid = nullptr,
                uint8_t algorithmID = OpenABE_SCHEME_AES_GCM);

  ~OpenABESymKey();

  // Methods
  std::string toString();
  uint8_t *getInternalPtr() { return (uint8_t *)&((this->m_keyData)[0]); }
  uint32_t getLength() { return this->m_keyData.size(); }
  OpenABEByteString& getKeyBytes() { return (this->m_keyData); }

  bool hashToSymmetricKey(GT &input, uint32_t keyLen);
  bool generateSymmetricKey(uint32_t keyLen);
  void setSymmetricKey(OpenABEByteString &key);

  OpenABE_ERROR exportKeyToBytes(OpenABEByteString &output);
  OpenABE_ERROR loadKeyFromBytes(OpenABEByteString &input);
  friend bool operator==(const OpenABESymKey&, const OpenABESymKey&);
};

///
/// @class  OpenABESymKeyAuthEnc
///
/// @brief  Class for performing authenticated symmetric encryption using AES in GCM mode
///

class OpenABESymKeyAuthEnc : ZObject {
private:
  EVP_CIPHER *cipher;
  uint8_t iv[AES_BLOCK_SIZE+1];
  OpenABEByteString aad;
  OpenABEByteString key;
  bool aad_set;
  uint32_t iv_len;

public:
  OpenABESymKeyAuthEnc(int securitylevel, const std::string& zkey);
  OpenABESymKeyAuthEnc(int securitylevel, OpenABEByteString& zkey);
  ~OpenABESymKeyAuthEnc();

  void setAddAuthData(OpenABEByteString &aad);
  void setAddAuthData(uint8_t* aad, uint32_t aad_len);
  OpenABE_ERROR encrypt(const std::string& plaintext, OpenABEByteString& iv,
                        OpenABEByteString& ciphertext, OpenABEByteString& tag);
  bool decrypt(std::string& plaintext, OpenABEByteString& iv,
               OpenABEByteString& ciphertext, OpenABEByteString& tag);
};


///
/// @class  OpenABESymKeyAuthEncStream
///
/// @brief  Class for streaming encryption and decryption using AES in GCM mode
///

class OpenABESymKeyAuthEncStream : ZObject {
private:
  EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx;
  OpenABEByteString the_iv, aad;

  std::shared_ptr<OpenABESymKey> key;
  bool aad_set, init_enc_set, init_dec_set;
  size_t total_ct_len, updateEncCount, updateDecCount;

public:
  OpenABESymKeyAuthEncStream(int securitylevel, const std::shared_ptr<OpenABESymKey>& key);
  ~OpenABESymKeyAuthEncStream();

  void initAddAuthData(uint8_t *aad, uint32_t aad_len);
  OpenABE_ERROR setAddAuthData(void);

  OpenABE_ERROR   encryptInit(OpenABEByteString& iv);
  OpenABE_ERROR   encryptUpdate(OpenABEByteString& plaintextBlock, OpenABEByteString& ciphertext);
  OpenABE_ERROR   encryptFinalize(OpenABEByteString& ciphertext, OpenABEByteString& tag);

  OpenABE_ERROR   decryptInit(OpenABEByteString& iv, OpenABEByteString& tag);
  OpenABE_ERROR   decryptUpdate(OpenABEByteString& ciphertextBlock, OpenABEByteString& plaintext);
  OpenABE_ERROR   decryptFinalize(OpenABEByteString& plaintext);
};


#endif /* ifdef  __ZSYMKEY_H__ */
