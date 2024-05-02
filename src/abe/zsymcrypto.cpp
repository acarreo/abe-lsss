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
/// \file   zsymcrypto.cpp
///
/// \brief  Thin wrappers for symmetric key scheme contexts.
///
/// \author Alan Dunn and J. Ayo Akinyele
///

#include <sstream>
#include <stdexcept>
#include <cassert>

#include "abe/zsymcrypto.h"
#include "abe/zkdf.h"

using namespace std;


namespace crypto {

/********************************************************************************
 * Implementation of the OpenABESymKeyAuthEnc class
 ********************************************************************************/

OpenABESymKeyAuthEnc::OpenABESymKeyAuthEnc(int securitylevel, const string& zkey): ZObject()
{
    if(securitylevel == DEFAULT_AES_SEC_LEVEL) {
        this->cipher = (EVP_CIPHER *) EVP_aes_256_gcm();
        // cout << "cipher_block_size: " << EVP_CIPHER_block_size(this->cipher) << endl;
    }
    this->iv_len = AES_BLOCK_SIZE;
    this->aad_set = false;
    this->key = zkey;
}

OpenABESymKeyAuthEnc::OpenABESymKeyAuthEnc(int securitylevel, OpenABEByteString& zkey): ZObject()
{
    if(securitylevel == DEFAULT_AES_SEC_LEVEL) {
        this->cipher = (EVP_CIPHER *) EVP_aes_256_gcm();
        // cout << "cipher_block_size: " << EVP_CIPHER_block_size(this->cipher) << endl;
    }
    this->iv_len = AES_BLOCK_SIZE;
    this->aad_set = false;
    this->key = zkey;
}


OpenABESymKeyAuthEnc::~OpenABESymKeyAuthEnc() {
    if (this->aad_set) {
        this->aad.zeroize();
    }
}

void
OpenABESymKeyAuthEnc::chooseRandomIV() {
    getRandomBytes(this->iv, AES_BLOCK_SIZE);
}

void
OpenABESymKeyAuthEnc::setAddAuthData(OpenABEByteString &aad) {
    if(aad.size() == 0) {
        // fill AAD buffer with 0's
        this->aad.fillBuffer(0, AES_BLOCK_SIZE);
    }
    else {
        // copy 'aad'
        this->aad = aad;
    }
    this->aad_set = true;
}

void
OpenABESymKeyAuthEnc::setAddAuthData(uint8_t *aad, uint32_t aad_len) {
    this->aad.clear();
    if(aad) {
        this->aad.appendArray(aad, aad_len);
    } else {
        // fill AAD buffer with 0's
        this->aad.fillBuffer(0, AES_BLOCK_SIZE);
    }
    this->aad_set = true;
}

void OpenABESymKeyHandle::decrypt(string& plaintext, const string& ciphertext)
{
  unique_ptr<OpenABESymKeyAuthEnc> symkeyContext_(new OpenABESymKeyAuthEnc(security_level_, key_));
    }
    if (ct)
        free(ct);
    return result;
}
    OpenABEByteString ziv, zct, ztag;
    }

    // set the additional auth data (if set)
    if (authData_.size() > 0) {
      symkeyContext_->setAddAuthData(authData_);
    } else {
      symkeyContext_->setAddAuthData(NULL, 0);
    }
    bool dec_status = symkeyContext_->decrypt(plaintext, ziv, zct, ztag);
    }
}

/********************************************************************************
 * Implementation of the SymKeyEncHandler class
 ********************************************************************************/
SymKeyEncHandler::SymKeyEncHandler() : ZObject() {
  this->encryption_mode_ = EncryptionMode::GCM;
  this->authData_ = OpenABEByteString();
  this->b64_encode_ = false;
}

SymKeyEncHandler::SymKeyEncHandler(const string& key, EncryptionMode mode,
                                   bool apply_b64_encode) : ZObject()
{
  this->b64_encode_ = apply_b64_encode;
  this->encryption_mode_ = mode;
  this->setSKEHandler(key);
}

SymKeyEncHandler::SymKeyEncHandler(const shared_ptr<OpenABESymKey>& key,
                                   EncryptionMode mode, bool apply_b64_encode) : ZObject()
{
  this->b64_encode_ = apply_b64_encode;
  this->encryption_mode_ = mode;
  this->setSKEHandler(key);
}

SymKeyEncHandler::~SymKeyEncHandler() {
  cbc_handler_.reset();
  gcm_handler_.reset();
}

void SymKeyEncHandler::setSKEHandler(const std::shared_ptr<OpenABESymKey>& key) {
  OpenABEByteString keyBytes;
  keyBytes = key->getKeyBytes();
  switch (this->encryption_mode_) {
    case EncryptionMode::CBC:
      this->cbc_handler_ = std::make_unique<OpenABESymKeyEnc>(keyBytes.toString());
      break;
    case EncryptionMode::GCM:
      this->gcm_handler_ = std::make_unique<OpenABESymKeyAuthEnc>(DEFAULT_AES_SEC_LEVEL, keyBytes);
      break;
    default:
      throw OpenABE_ERROR_UNKNOWN_SCHEME;
  }
  this->key_ = key;
}

void SymKeyEncHandler::setSKEHandler(const std::string& key) {
  OpenABEByteString keyBytes;
  keyBytes = key;
  switch (this->encryption_mode_) {
    case EncryptionMode::CBC:
      this->cbc_handler_ = std::make_unique<OpenABESymKeyEnc>(key);
      break;
    case EncryptionMode::GCM:
      this->gcm_handler_ = std::make_unique<OpenABESymKeyAuthEnc>(DEFAULT_AES_SEC_LEVEL, keyBytes);
      break;
    default:
      throw OpenABE_ERROR_UNKNOWN_SCHEME;
  }
  this->key_ = make_shared<OpenABESymKey>();
  this->key_->setSymmetricKey(keyBytes);
}

void SymKeyEncHandler::setAuthData(const OpenABEByteString& authData) {
  this->authData_ = authData;
}

std::string SymKeyEncHandler::encrypt(const std::string& plaintext) {
  OpenABEByteString zciphertext;
  OpenABEByteString ziv, zct, ztag;
  string ciphertext;

  switch (this->encryption_mode_) {
    case EncryptionMode::CBC:
      try
      {
        OpenABE_ERROR error = cbc_handler_->encrypt(plaintext, ziv, zct);
        if (error != OpenABE_NOERROR) {
          throw error;
        }

        zciphertext.smartPack(ziv);
        zciphertext.smartPack(zct);
      }
      catch(OpenABE_ERROR& error) {
        throw runtime_error(OpenABE_errorToString(error));
      }

      break;

    case EncryptionMode::GCM:
      try {
        // set the additional auth data (if set)
        if (this->authData_.size() > 0) {
          gcm_handler_->setAddAuthData(this->authData_);
        } else {
          gcm_handler_->setAddAuthData(NULL, 0);
        }
        // now we can encrypt with sym key
        if (gcm_handler_->encrypt(plaintext, ziv, zct, ztag) != OpenABE_NOERROR) {
          throw runtime_error("Encryption failed");
        }

        zciphertext.smartPack(ziv);
        zciphertext.smartPack(zct);
        zciphertext.smartPack(ztag);
      }
      catch (OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
      }
      break;

    default:
      throw OpenABE_ERROR_UNKNOWN_SCHEME;
  }

  if (this->b64_encode_) {
    ciphertext = Base64Encode(zciphertext.data(), zciphertext.size());
  } else {
    ciphertext = zciphertext.toString();
  }

  return ciphertext;
}

std::string SymKeyEncHandler::decrypt(const std::string& ciphertext) {
  string plaintext;
  OpenABEByteString zciphertext, ziv, zct, ztag;
  size_t index = 0;

  if (this->b64_encode_) {
    zciphertext = Base64Decode(ciphertext);
  } else {
    zciphertext = ciphertext;
  }

  ziv = zciphertext.smartUnpack(&index);
  zct = zciphertext.smartUnpack(&index);

  switch (encryption_mode_) {
    case EncryptionMode::CBC:
      try {
        if (!cbc_handler_->decrypt(plaintext, ziv, zct)) {
          throw OpenABE_ERROR_DECRYPTION_FAILED;
        }
      } catch (OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
      }
      break;

    case EncryptionMode::GCM:
      try {
        ztag = zciphertext.smartUnpack(&index);
        if (this->authData_.size() > 0) {
          gcm_handler_->setAddAuthData(this->authData_);
        } else {
          gcm_handler_->setAddAuthData(NULL, 0);
        }

        if (!gcm_handler_->decrypt(plaintext, ziv, zct, ztag)) {
          throw OpenABE_ERROR_DECRYPTION_FAILED;
        }
      } catch(const OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
      }
      break;

    default:
      throw OpenABE_ERROR_UNKNOWN_SCHEME;
  }

  return plaintext;
}
