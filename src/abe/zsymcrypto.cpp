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


/********************************************************************************
 * Implementation of the OpenABESymKeyHandle class
 ********************************************************************************/

OpenABESymKeyHandle::OpenABESymKeyHandle(const string& keyBytes, bool apply_b64_encode) {
  try {
    if (keyBytes.size() != DEFAULT_SYM_KEY_BYTES) {
      throw OpenABE_ERROR_INVALID_LENGTH;
    }

    security_level_ = DEFAULT_AES_SEC_LEVEL;
  } catch (OpenABE_ERROR& error) {
    string msg = OpenABE_errorToString(error);
    throw runtime_error(msg);
  }

  key_ = keyBytes;
  b64_encode_ = apply_b64_encode;
}

OpenABESymKeyHandle::OpenABESymKeyHandle(OpenABEByteString& keyBytes,
                                     OpenABEByteString& authData, bool apply_b64_encode) {
  try {
    key_ = keyBytes.toString();
    if (key_.size() != DEFAULT_SYM_KEY_BYTES) {
      throw OpenABE_ERROR_INVALID_LENGTH;
    }

    security_level_ = DEFAULT_AES_SEC_LEVEL;
  } catch (OpenABE_ERROR& error) {
    string msg = OpenABE_errorToString(error);
    throw runtime_error(msg);
  }

  authData_ = authData;
  b64_encode_ = apply_b64_encode;
}


OpenABESymKeyHandle::~OpenABESymKeyHandle() {
    key_.clear();
    authData_.clear();
}

void OpenABESymKeyHandle::encrypt(string& ciphertext, const string& plaintext)
{
  unique_ptr<OpenABESymKeyAuthEnc> symkeyContext_(new OpenABESymKeyAuthEnc(security_level_, key_));
  try {
    OpenABEByteString zciphertext, ziv, zct, ztag;
    // set the additional auth data (if set)
    if (authData_.size() > 0) {
      symkeyContext_->setAddAuthData(authData_);
    } else {
      symkeyContext_->setAddAuthData(NULL, 0);
    }
    // now we can encrypt with sym key
    if (symkeyContext_->encrypt(plaintext, ziv, zct, ztag) != OpenABE_NOERROR) {
      throw runtime_error("Encryption failed");
    }

    // serialize all three ziv, zciphertext and ztag
    // cout << "<=== ENCRYPT ===>" << endl;
    // cout << "iv: " << ziv.toLowerHex() << endl;
    // cout << "ct: " << zct.toLowerHex() << endl;
    // cout << "tg: " << ztag.toLowerHex() << endl;
    // cout << "<=== ENCRYPT ===>" << endl;

    zciphertext.smartPack(ziv);
    zciphertext.smartPack(zct);
    zciphertext.smartPack(ztag);
    string s = zciphertext.toString();
    if (b64_encode_) {
      // output base64 encoded version
      ciphertext = Base64Encode((const unsigned char *)s.c_str(), s.size());
    } else {
      // output binary (caller handles encoding format)
      ciphertext = s;
    }
  } catch (OpenABE_ERROR& error) {
    string msg = OpenABE_errorToString(error);
    throw runtime_error(msg);
  }
}

void OpenABESymKeyHandle::decrypt(string& plaintext, const string& ciphertext)
{
  unique_ptr<OpenABESymKeyAuthEnc> symkeyContext_(new OpenABESymKeyAuthEnc(security_level_, key_));
  try {
    size_t index = 0;
    OpenABEByteString zciphertext;
    if (b64_encode_) {
      zciphertext += Base64Decode(ciphertext);
    } else {
      zciphertext += ciphertext;
    }
    OpenABEByteString ziv, zct, ztag;
    ziv = zciphertext.smartUnpack(&index);
    zct = zciphertext.smartUnpack(&index);
    ztag = zciphertext.smartUnpack(&index);

    // set the additional auth data (if set)
    if (authData_.size() > 0) {
      symkeyContext_->setAddAuthData(authData_);
    } else {
      symkeyContext_->setAddAuthData(NULL, 0);
    }
    bool dec_status = symkeyContext_->decrypt(plaintext, ziv, zct, ztag);
    if (!dec_status) {
      throw runtime_error("Decryption failed");
    }
  } catch (OpenABE_ERROR& error) {
    string msg = OpenABE_errorToString(error);
    throw runtime_error(msg);
  }
}

void
OpenABESymKeyHandle::exportRawKey(string& key) {
  key = this->key_;
}

void
OpenABESymKeyHandle::exportKey(string& key) {
  size_t key_len = this->key_.size();
  OpenABEByteString secret_key, salt, info, output_key;
  secret_key += this->key_;
  // info: export key is the label
  info += "export key";

  OpenABEKDF kdf;
  output_key = kdf.ComputeHKDF(secret_key, salt, info, key_len);
  key = output_key.toString();
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
  gcm_handler_.reset();
}

void SymKeyEncHandler::setSKEHandler(const std::shared_ptr<OpenABESymKey>& key) {
  OpenABEByteString keyBytes;
  keyBytes = key->getKeyBytes();

  auto algID = key->getAlgorithmID();
  auto scheme = SchemeFromEncryptionMode(this->encryption_mode_);
  if (algID != scheme && algID != OpenABE_SCHEME_NONE) {
    throw OpenABE_ERROR_INVALID_KEY;
  }

  switch (this->encryption_mode_) {
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
  auto keyPtr = make_shared<OpenABESymKey>();
  keyPtr->setSymmetricKey(keyBytes);
  this->setSKEHandler(keyPtr);
}

void SymKeyEncHandler::setAuthData(const OpenABEByteString& authData) {
  if (authData.size() > AES_BLOCK_SIZE) {
    OpenABEByteString aad;
    authData.hashToBytes(aad);
    this->authData_ = aad.getSubset(0, AES_BLOCK_SIZE);
  } else {
    this->authData_ = authData;
  }
}

OpenABE_ERROR SymKeyEncHandler::encrypt(OpenABEByteString& ciphertext,
                                        const OpenABEByteString& plaintext) {
  OpenABE_ERROR ret = OpenABE_ERROR_ENCRYPTION_ERROR;
  OpenABEByteString zciphertext;
  OpenABEByteString ziv, zct, ztag, aad;


  string plain_str = const_cast<OpenABEByteString&>(plaintext).toString();

  switch (this->encryption_mode_) {
    case EncryptionMode::GCM:
      try {
        // set the additional auth data (if set)
        if (this->authData_.size() > 0) {
          gcm_handler_->setAddAuthData(this->authData_);
          aad = this->authData_;
        } else {
          gcm_handler_->setAddAuthData(NULL, 0);
        }
        // now we can encrypt with sym key
        if (gcm_handler_->encrypt(plain_str, ziv, zct, ztag) != OpenABE_NOERROR) {
          throw runtime_error("Encryption failed");
        }

        zciphertext.smartPack(ziv);
        zciphertext.smartPack(zct);
        zciphertext.smartPack(ztag);
        zciphertext.smartPack(aad);
        ret = OpenABE_NOERROR;
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
    ciphertext = zciphertext;
  }

  return ret;
}

OpenABE_ERROR SymKeyEncHandler::decrypt(OpenABEByteString& plaintext,
                                        const OpenABEByteString& ciphertext) {
  OpenABE_ERROR ret = OpenABE_ERROR_DECRYPTION_FAILED;  
  OpenABEByteString zciphertext, ziv, zct, ztag, aad;
  string plain_str;
  size_t index = 0;

  if (this->b64_encode_) {
    zciphertext = Base64Decode(const_cast<OpenABEByteString&>(ciphertext).toString());
  } else {
    zciphertext = ciphertext;
  }

  ziv = zciphertext.smartUnpack(&index);
  zct = zciphertext.smartUnpack(&index);

  switch (encryption_mode_) {
    case EncryptionMode::GCM:
      try {
        // The tag is the final element in the ciphertext. It is always present
        // and has a fixed size of AES_BLOCK_SIZE.
        if (index < zciphertext.size()) { // If the ciphertext (zct) is empty
          ztag = zciphertext.smartUnpack(&index);
          if (index < zciphertext.size()) {
            aad = zciphertext.smartUnpack(&index);
          }
        } else {
          ztag = zct; zct.clear();
        }

        if (this->authData_.size() > 0) {
          if (aad.size() != 0 && aad != this->authData_) {
            std::cerr << "-----------> " << typeid(*this).name() << "::" << __func__
                      << " -- Error: Invalid additional authentication data" << std::endl;
            throw OpenABE_ERROR_DECRYPTION_FAILED;
          }
          gcm_handler_->setAddAuthData(this->authData_);
        } else if (aad.size() > 0) {
          gcm_handler_->setAddAuthData(aad);
        } else {
          gcm_handler_->setAddAuthData(NULL, 0);
        }

        if (!gcm_handler_->decrypt(plain_str, ziv, zct, ztag)) {
          throw OpenABE_ERROR_DECRYPTION_FAILED;
        }
        plaintext = plain_str;
        ret = OpenABE_NOERROR;
      } catch(const OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
      }
      break;

    default:
      throw OpenABE_ERROR_UNKNOWN_SCHEME;
  }

  return ret;
}

std::string SymKeyEncHandler::encrypt(const std::string& plaintext) {
  OpenABEByteString zplaintext, zciphertext;
  try
  {
    zplaintext = plaintext;
    OpenABE_ERROR error = encrypt(zciphertext, zplaintext);
    if (error != OpenABE_NOERROR) {
      throw runtime_error(OpenABE_errorToString(error));
    }
    return zciphertext.toString();
  } catch(const runtime_error& e) {
    std::cerr << e.what() << '\n';
  }
  return "";
}

std::string SymKeyEncHandler::decrypt(const std::string& ciphertext) {
  OpenABEByteString zplaintext, zciphertext;
  try
  {
    zciphertext = ciphertext;
    OpenABE_ERROR error = decrypt(zplaintext, zciphertext);
    if (error != OpenABE_NOERROR) {
      throw runtime_error(OpenABE_errorToString(error));
    }
    return zplaintext.toString();
  } catch(const runtime_error& e) {
    std::cerr << e.what() << '\n';
  }
  return "";
}

OpenABE_SCHEME SchemeFromEncryptionMode(EncryptionMode mode) {
  switch (mode) {
    case EncryptionMode::CBC:
      return OpenABE_SCHEME_AES_CBC;
    case EncryptionMode::GCM:
      return OpenABE_SCHEME_AES_GCM;
    case EncryptionMode::STREAM_GCM:
      return OpenABE_SCHEME_AES_GCM_STREAM;
    default:
      return OpenABE_SCHEME_NONE;
  }
}