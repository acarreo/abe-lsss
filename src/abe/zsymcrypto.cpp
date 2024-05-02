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
 * Implementation of the OpenABESymKeyHandleImpl class
 ********************************************************************************/

OpenABESymKeyHandleImpl::OpenABESymKeyHandleImpl(const string& keyBytes, bool apply_b64_encode) {
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

OpenABESymKeyHandleImpl::OpenABESymKeyHandleImpl(OpenABEByteString& keyBytes,
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


OpenABESymKeyHandleImpl::~OpenABESymKeyHandleImpl() {
    key_.clear();
    authData_.clear();
}

void OpenABESymKeyHandleImpl::encrypt(string& ciphertext, const string& plaintext)
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
        if (symkeyContext_->encrypt(plaintext, &ziv, &zct, &ztag) != OpenABE_NOERROR) {
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

void OpenABESymKeyHandleImpl::decrypt(string& plaintext, const string& ciphertext)
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
        bool dec_status = symkeyContext_->decrypt(plaintext, &ziv, &zct, &ztag);
        if (!dec_status) {
            throw runtime_error("Decryption failed");
        }
    } catch (OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
    }
}

void
OpenABESymKeyHandleImpl::exportRawKey(string& key) {
    key = this->key_;
}

void
OpenABESymKeyHandleImpl::exportKey(string& key) {
    size_t key_len = this->key_.size();
	OpenABEByteString secret_key, salt, info, output_key;
	secret_key += this->key_;
	// info: export key is the label
	info += "export key";

    OpenABEKDF kdf;
    output_key = kdf.ComputeHKDF(secret_key, salt, info, key_len);
	key = output_key.toString();
}

}
