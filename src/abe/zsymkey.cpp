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
/// \file   zsymkey.cpp
///
/// \brief  Implementation for storing and manipulating
///         the symmetric enc OpenABE keys
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABESYMKEY_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cmath>

#include "abe/zsymkey.h"
#include "abe/zkdf.h"

using namespace std;

/********************************************************************************
 * Implementation of the OpenABESymKey class
 ********************************************************************************/

/*!
 * Destructor for the STKSymKey class.
 *
 */
OpenABESymKey::~OpenABESymKey() {
    // Zeroize contents of key buffer
    this->m_keyData.zeroize();
}

OpenABE_ERROR OpenABESymKey::loadKeyFromBytes(OpenABEByteString &input) {
  if (input.size() == 0) {
    return OpenABE_ERROR_INVALID_LENGTH;
  }

  OpenABEByteString header, idBytes, uid, keyBytes;

  size_t index = 0, h_index = 0;
  size_t id_len = 0;
  uint8_t algoID, libVersion;

  header = input.smartUnpack(&index);
  id_len = header.size() - UID_LEN - sizeof(algoID) - sizeof(libVersion);

  libVersion = header.at(h_index++);
  algoID = header.at(h_index++);
  uid = header.getSubset(h_index, UID_LEN); h_index += UID_LEN;
  idBytes = header.getSubset(h_index, id_len);

  OpenABESymKey key(idBytes.toString(), &uid, algoID);

  // Set the key data
  keyBytes = input.smartUnpack(&index);
  key.setSymmetricKey(keyBytes);

  *this = key;

  return OpenABE_NOERROR;
}

OpenABE_ERROR OpenABESymKey::exportKeyToBytes(OpenABEByteString &output) {
  OpenABEByteString header;
  this->getHeader(header);

  output.clear();
  output.smartPack(header);
  output.smartPack(this->m_keyData);
  return OpenABE_NOERROR;
}

/*!
 * Debugging function. Outputs a symmetric key in a human-readable
 * string format. Don't use this in production code!
 *
 * @return  Key as a formatted string.
 */
string OpenABESymKey::toString() { return this->m_keyData.toHex(); }

/*!
 * Hashes a group element into a symmetric key.
 *
 * @throw  An exception if there's an error.
 */

bool OpenABESymKey::hashToSymmetricKey(GT &input, uint32_t keyLen) {
  size_t h_len = 0;
  OpenABEByteString h_input;

  uint8_t* h_in = input.hashToBytes(&h_len);
  h_input.appendArray(h_in, h_len);

  OpenABEByteString key = OpenABEKDF().ComputeKDF2(h_input, keyLen);
  this->setSymmetricKey(key);

  return true;
}

bool OpenABESymKey::generateSymmetricKey(uint32_t keyLen) {
  OpenABEByteString key;
  getRandomBytes(key, (int)keyLen);

  this->setSymmetricKey(key);
  return true;
}

void OpenABESymKey::setSymmetricKey(OpenABEByteString &key) {
  if (key.size() != SYM_KEY_BYTES && key.size() != DEFAULT_SYM_KEY_BYTES) {
    throw OpenABE_ERROR_INVALID_LENGTH;
  }

  this->m_keyData.clear();
  this->m_keyData = key;
}

bool operator==(const OpenABESymKey &lhs, const OpenABESymKey &rhs) {
  OpenABEByteString lhs_header, rhs_header;
  lhs.getHeader(lhs_header); rhs.getHeader(rhs_header);
  return (lhs_header == rhs_header && lhs.m_keyData == lhs.m_keyData);
}

/********************************************************************************
 * Implementation of the OpenABESymKeyEnc class
 ********************************************************************************/

OpenABESymKeyEnc::OpenABESymKeyEnc(string key) : ZObject() {
  this->seclevel = DEFAULT_SECURITY_LEVEL;
  this->keyStr = key;
  this->key = (AES_KEY *)malloc(sizeof(AES_KEY));
  MALLOC_CHECK_OUT_OF_MEMORY(this->key);
  memset(this->iv, 0, AES_BLOCK_SIZE + 1);
  this->iv_set = false;
  this->status = false;
}

OpenABESymKeyEnc::OpenABESymKeyEnc(int securitylevel, string key) : ZObject() {
  this->seclevel = securitylevel;
  this->keyStr = key;
  this->key = (AES_KEY *)malloc(sizeof(AES_KEY));
  MALLOC_CHECK_OUT_OF_MEMORY(this->key);
  memset(this->iv, 0, AES_BLOCK_SIZE + 1);
  this->iv_set = false;
  this->status = false;
}

OpenABESymKeyEnc::OpenABESymKeyEnc(int securitylevel, uint8_t *iv, string key)
    : ZObject() {
  /* copy iv and key into */
  this->seclevel = securitylevel;
  memset(this->iv, 0, AES_BLOCK_SIZE + 1);
  memcpy(this->iv, iv, AES_BLOCK_SIZE + 1);
  this->iv_set = true;
  this->keyStr = key;
  this->key = (AES_KEY *)malloc(sizeof(AES_KEY));
  MALLOC_CHECK_OUT_OF_MEMORY(this->key);
  this->status = false;
}

OpenABESymKeyEnc::~OpenABESymKeyEnc() { SAFE_FREE(this->key); }

OpenABE_ERROR
OpenABESymKeyEnc::encrypt(const string& plaintext, OpenABEByteString& iv,
                          OpenABEByteString& ciphertext)
{
  // select a new IV
  if (!this->iv_set) {
    getRandomBytes(this->iv, AES_BLOCK_SIZE);
  }

  // instantiate AES_KEY
  AES_set_encrypt_key((uint8_t *)this->keyStr.c_str(), this->seclevel,
                      this->key);

  // compute ciphertext size and round to nearest block
  uint32_t plaintext_len = plaintext.size();
  int ct_len = (int)ceil((plaintext_len) / (double)(AES_BLOCK_SIZE)) * AES_BLOCK_SIZE;

  // Je ne sais pas pourquoi le premier bloc du déchiffré est différent de celui
  // du clair de départ. J'ai donc ajouté un bloc de AES_BLOCK_SIZE 0 au début du clair
  // pour que le premier bloc du déchiffré soit le même que celui du clair de départ.
  // J'ignore ce premier bloc lors du déchiffrement.
  uint8_t modified_plaintext[plaintext_len + AES_BLOCK_SIZE];
  memset(modified_plaintext, 0, plaintext_len + AES_BLOCK_SIZE);
  memcpy(modified_plaintext + AES_BLOCK_SIZE, plaintext.c_str(), plaintext_len);

  iv.clear();
  iv.appendArray(this->iv, AES_BLOCK_SIZE);

  ciphertext.clear();
  ciphertext.fillBuffer(0, ct_len + AES_BLOCK_SIZE);
  AES_cbc_encrypt(modified_plaintext, ciphertext.getInternalPtr(), ct_len + AES_BLOCK_SIZE,
                  this->key, this->iv, AES_ENCRYPT);

  return OpenABE_NOERROR;
}

bool
OpenABESymKeyEnc::decrypt(string& plaintext, OpenABEByteString& iv,
                              OpenABEByteString& ciphertext) {

  if (iv.size() != AES_BLOCK_SIZE) {
    return false;
  }

  if (!this->iv_set) {
    memset(this->iv, 0, AES_BLOCK_SIZE);
    memcpy(this->iv, iv.data(), AES_BLOCK_SIZE);
  }

  // instantiate AES_KEY
  AES_set_decrypt_key((uint8_t *)this->keyStr.c_str(), this->seclevel, this->key);

  uint32_t ct_len = ciphertext.size();
  uint32_t pt_len = ct_len; // - AES_BLOCK_SIZE;
  OpenABEByteString plain;
  plain.fillBuffer(0, pt_len);

  AES_cbc_encrypt(ciphertext.data(), plain.getInternalPtr(), ct_len, this->key, this->iv,
                  AES_DECRYPT);

  plaintext = string((char *)plain.getInternalPtr() + AES_BLOCK_SIZE, pt_len - AES_BLOCK_SIZE);

  return true;
}


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

OpenABE_ERROR
OpenABESymKeyAuthEnc::encrypt(const string& plaintext, OpenABEByteString& iv,
                              OpenABEByteString& ciphertext, OpenABEByteString& tag)
{
  OpenABE_ERROR result = OpenABE_NOERROR;
  uint8_t *ct = nullptr;

  try {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OpenABEByteString ivObj, ctObj, tagObj;
    uint8_t *pt_ptr = (uint8_t *) plaintext.c_str();
    int len = 0, ctlen, pt_len = plaintext.size();
    if(pt_len < AES_BLOCK_SIZE)
      /* add block size to the len */
      len += AES_BLOCK_SIZE;
    else
      /* add pt_len + block size to len */
      len += pt_len;
    // allocate the temp output ciphertext buffer
    // uint8_t ct[len+1];
    ct = (uint8_t*) malloc(len+1);
    MALLOC_CHECK_OUT_OF_MEMORY(ct);
    memset(ct, 0, len+1);

    // cout << "Plaintext:\n";
    // BIO_dump_fp(stdout, (const char *) &((*plaintext)[0]), plaintext->size());
    // cout << "Enc Key:\n";
    // BIO_dump_fp(stdout, (const char *) this->key.getInternalPtr(), this->key.size());

    /* set cipher type and mode */
    EVP_EncryptInit_ex(ctx, this->cipher, NULL, NULL, NULL);
    /* set the IV length as 128-bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_BLOCK_SIZE, NULL);

    /* initialize key and IV */
    getRandomBytes(this->iv, AES_BLOCK_SIZE);
    EVP_EncryptInit_ex(ctx, NULL, NULL, this->key.getInternalPtr(), this->iv);
    iv.clear();
    iv.appendArray(this->iv, this->iv_len);

    /* specify the additional authentication data (aad) */
    if (this->aad_set) {
        EVP_EncryptUpdate(ctx, NULL, &ctlen, this->aad.getInternalPtr(), this->aad.size());
    }

    /* encrypt plaintext */
    EVP_EncryptUpdate(ctx, ct, &ctlen, pt_ptr, pt_len);

    // cout << "Ciphertext:\n";
    // BIO_dump_fp(stdout, (const char *) ct, ctlen);
    ciphertext.clear();
    ciphertext.appendArray(ct, ctlen);

    /* finalize: computes authentication tag*/
    EVP_EncryptFinal_ex(ctx, ct, &len);
    // For AES-GCM, the 'len' should be '0' because there is no extra bytes used for padding.
    ASSERT(len == 0, OpenABE_ERROR_UNEXPECTED_EXTRA_BYTES);

    /* retrieve the tag */
    int tag_len = AES_BLOCK_SIZE;
    uint8_t tag_buf[tag_len+1];
    memset(tag_buf, 0, tag_len+1);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag_buf);

    // cout << "Tag:\n";
    // BIO_dump_fp(stdout, (const char *) tag_buf, tag_len);
    tag.clear();
    tag.appendArray(tag_buf, tag_len);

    EVP_CIPHER_CTX_free(ctx);
  } catch(OpenABE_ERROR& e) {
    result = e;
  }
  if (ct)
    free(ct);
  return result;
}

bool
OpenABESymKeyAuthEnc::decrypt(string& plaintext, OpenABEByteString& iv,
                              OpenABEByteString& ciphertext, OpenABEByteString& tag)
{
  if(ciphertext.size() == 0) {
    /* ciphertext has to be greater than 0 */
    return false;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  uint8_t *pt = nullptr;
  OpenABEByteString pt_buf;

  int pt_len, retValue;
  uint8_t *ct_ptr = ciphertext.getInternalPtr();
  int ct_len = ciphertext.size();
  // cout << "Dec Ciphertext:\n";
  // BIO_dump_fp(stdout, (const char *) ct_ptr, ct_len);

  uint8_t *tag_ptr =  tag.getInternalPtr();
  int tag_len = tag.size();
  ASSERT(tag_len == AES_BLOCK_SIZE, OpenABE_ERROR_INVALID_TAG_LENGTH);
  // cout << "Dec Tag:\n";
  // BIO_dump_fp(stdout, (const char *) tag_ptr, tag_len);

  /* set cipher type and mode */
  EVP_DecryptInit_ex(ctx, this->cipher, NULL, NULL, NULL);
  /* set the IV length as 128-bits */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
  /* specify key and iv */
  // cout << "Dec Key:\n";
  // BIO_dump_fp(stdout, (const char *) this->key.getInternalPtr(), this->key.size());
  EVP_DecryptInit_ex(ctx, NULL, NULL, this->key.getInternalPtr(), iv.getInternalPtr());

  // OpenSSL says tag must be set *before* any EVP_DecryptUpdate call.
  // This is a restriction for OpenSSL v1.0.1c and prior versions but also works
  // thesame for later versions. To avoid OpenSSL version checks, we set the tag
  // here which should work across all versions.
  /* set the tag expected value */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag_ptr);

  /* specify additional authentication data */
  if(this->aad_set) {
    EVP_DecryptUpdate(ctx, NULL, &pt_len, this->aad.getInternalPtr(), this->aad.size());
  }

  // uint8_t pt[ct_len+1];
  pt = (uint8_t*) malloc(ct_len+1);
  MALLOC_CHECK_OUT_OF_MEMORY(pt);
  memset(pt, 0, ct_len+1);
  /* decrypt and store plaintext in pt buffer */
  EVP_DecryptUpdate(ctx, pt, &pt_len, ct_ptr, ct_len);
  pt_buf.appendArray(pt, (uint32_t) pt_len);

  // cout << "Plaintext:\n";
  // BIO_dump_fp(stdout, (const char *) pt, pt_len);

  /* finalize decryption */
  retValue = EVP_DecryptFinal_ex(ctx, pt, &pt_len);
  if (pt) {
    free(pt);
  }
  // printf("Tag Verify %s\n", retValue > 0 ? "Successful!" : "Failed!");

  EVP_CIPHER_CTX_free(ctx);
  if(retValue > 0) {
    /* tag verification successful */
    plaintext = pt_buf.toString();
    pt_buf.zeroize();
    return true;
  }
  else {
    /* authentication failure */
    return false;
  }
}


/********************************************************************************
 * Implementation of the OpenABESymKeyAuthEncStream class
 ********************************************************************************/

OpenABESymKeyAuthEncStream::OpenABESymKeyAuthEncStream(
    int securitylevel, const std::shared_ptr<OpenABESymKey> &key)
    : ZObject() {
  if (securitylevel == DEFAULT_AES_SEC_LEVEL) {
    this->cipher = (EVP_CIPHER *)EVP_aes_256_gcm();
    // cout << "cipher_block_size: " << EVP_CIPHER_block_size(this->cipher) <<
    // endl;
  }
  this->key = key;
  this->aad_set = false;
  this->init_enc_set = false;
  this->init_dec_set = false;
  this->total_ct_len = -1;
  this->updateEncCount = -1;
  this->updateDecCount = -1;
  this->ctx = NULL;
}

OpenABESymKeyAuthEncStream::~OpenABESymKeyAuthEncStream() {
  if (this->ctx != NULL)
    EVP_CIPHER_CTX_free(this->ctx);
}

void OpenABESymKeyAuthEncStream::initAddAuthData(uint8_t *aad, uint32_t aad_len) {
  if (this->init_enc_set || this->init_dec_set) {
    if (aad == NULL) {
      // fill AAD buffer with 0's
      this->aad.fillBuffer(0, AES_BLOCK_SIZE);
    } else {
      this->aad.appendArray(aad, aad_len);
    }
    this->aad_set = true;
  }
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::setAddAuthData() {
  /* specify the additional authentication data (aad) */
  uint8_t *aad_ptr = this->aad.getInternalPtr();
  int aad_len = this->aad.size();
  int ct_len = 0;

  if (this->init_enc_set && this->aad_set) {
    EVP_EncryptUpdate(this->ctx, NULL, &ct_len, aad_ptr, aad_len);
    ASSERT(ct_len == aad_len, OpenABE_ERROR_INVALID_INPUT);
  } else if (this->init_dec_set && this->aad_set) {
    EVP_DecryptUpdate(this->ctx, NULL, &ct_len, aad_ptr, aad_len);
    ASSERT(ct_len == aad_len, OpenABE_ERROR_INVALID_INPUT);
  } else {
    return OpenABE_INVALID_INPUT_TYPE;
  }

  return OpenABE_NOERROR;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::encryptInit(OpenABEByteString& iv) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  try {
    if (!this->init_enc_set) {
      /* can't mix encryptInit AND decryptInit at the same time */
      ASSERT(!this->init_dec_set, OpenABE_ERROR_INVALID_INPUT);
      this->ctx = EVP_CIPHER_CTX_new();
      /* set cipher type and mode */
      EVP_EncryptInit_ex(this->ctx, this->cipher, NULL, NULL, NULL);
      /* set the IV length as 128-bits (or 16 bytes) */
      EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_SET_IVLEN, AES_BLOCK_SIZE,
                          NULL);
      /* initialize key and IV */
      getRandomBytes(this->the_iv, AES_BLOCK_SIZE);

      EVP_EncryptInit_ex(this->ctx, NULL, NULL, this->key->getInternalPtr(),
                         this->the_iv.getInternalPtr());
      /* save the generated IV */
      iv.clear();
      iv = this->the_iv;
      /* initialize internal counters and state */
      this->total_ct_len = 0;
      this->updateEncCount = 0;
      this->init_enc_set = true;
    } else {
      throw OpenABE_ERROR_IN_USE_ALREADY;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::encryptUpdate(OpenABEByteString& plaintextBlock,
                                                OpenABEByteString& ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  if (this->init_enc_set) {
    /* encrypt plaintext */
    uint8_t *pt_ptr = plaintextBlock.getInternalPtr();
    int pt_len = plaintextBlock.size();
    int ct_len = 0;
    /* make sure that the plaintext is at least 1 byte (since AES-GCM works on
     * non-aligned block sizes) */
    ASSERT(pt_len > 0, OpenABE_ERROR_INVALID_INPUT);

    /* perform encryption update on the given plaintext */
    uint8_t ct[pt_len + 1];
    memset(ct, 0, pt_len);
    EVP_EncryptUpdate(this->ctx, ct, &ct_len, pt_ptr, pt_len);
    /* make sure we are not writing more than we've allocated */
    ASSERT(pt_len == ct_len, OpenABE_ERROR_INVALID_INPUT);
    /* keep track of the total ciphertext length so far*/
    this->total_ct_len += ct_len;
    /* return back to user */
    ciphertext.appendArray(ct, ct_len);
    /* increment number of encrypt updates the user has performed */
    this->updateEncCount++;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::encryptFinalize(OpenABEByteString& ciphertext,
                                                  OpenABEByteString& tag) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  if (this->init_enc_set && this->updateEncCount > 0) {
    /* finalize: computes authentication tag*/
    uint8_t *ct_ptr = ciphertext.getInternalPtr();
    /* make sure 'ct' size is the same as our internal size counter */
    ASSERT(ciphertext.size() == this->total_ct_len, OpenABE_ERROR_INVALID_INPUT);
    /* now we can finalize encryption */
    EVP_EncryptFinal_ex(this->ctx, ct_ptr, (int *)&this->total_ct_len);
    // For AES-GCM, the 'len' should be '0' because there is no extra bytes used
    // for padding.
    ASSERT(this->total_ct_len == 0, OpenABE_ERROR_UNEXPECTED_EXTRA_BYTES);

    /* retrieve the tag */
    int tag_len = AES_BLOCK_SIZE;
    uint8_t tag_ptr[tag_len + 1];
    memset(tag_ptr, 0, tag_len + 1);
    EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag_ptr);
    //    cout << "Tag:\n";
    //    BIO_dump_fp(stdout, (const char *) tag, tag_len);
    tag.appendArray(tag_ptr, tag_len);

    // house keeping
    this->updateEncCount = 0;
    EVP_CIPHER_CTX_free(this->ctx);
    this->ctx = NULL;
    // clear some buffers
    this->the_iv.fillBuffer(0, this->the_iv.size());
    this->aad.fillBuffer(0, this->aad.size());
    this->aad_set = false;
    // reset state
    this->init_enc_set = false;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::decryptInit(OpenABEByteString& iv,
                                              OpenABEByteString& tag) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  try {
    if (!this->init_dec_set) {
      /* can't mix encryptInit AND decryptInit at the same time */
      ASSERT(!this->init_enc_set, OpenABE_ERROR_INVALID_INPUT);

      /* allocate cipher context */
      this->ctx = EVP_CIPHER_CTX_new();

      /* set cipher type and mode */
      EVP_DecryptInit_ex(this->ctx, this->cipher, NULL, NULL, NULL);
      /* set the IV length as 128-bits (or 16 bytes) */
      EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
      /* specify key and iv */
      //	cout << "Deckey:\n";
      //	BIO_dump_fp(stdout, (const char *) this->key->getInternalPtr(),
      // this->key->getLength());
      EVP_DecryptInit_ex(this->ctx, NULL, NULL, this->key->getInternalPtr(),
                         iv.getInternalPtr());

      /* set the tag BEFORE any calls to decrypt update
      NOTE: the tag isn't checked until decrypt finalize (i.e., once we've
      obtained all the blocks) */
      EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                          tag.getInternalPtr());
      this->init_dec_set = true;
      this->updateDecCount = 0;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::decryptUpdate(OpenABEByteString& ciphertextBlock,
                                                OpenABEByteString& plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    if (this->init_dec_set) {
      ASSERT(ciphertextBlock.size() > 0, OpenABE_ERROR_INVALID_INPUT);
      /* perform decrypt update */
      int ct_len = ciphertextBlock.size();
      uint8_t *ct_ptr = ciphertextBlock.getInternalPtr();
      int pt_len = 0;

      uint8_t pt[ct_len + 1];
      memset(pt, 0, ct_len + 1);
      /* decrypt and store plaintext in pt buffer */
      EVP_DecryptUpdate(this->ctx, pt, &pt_len, ct_ptr, ct_len);
      ASSERT(pt_len == ct_len, OpenABE_ERROR_BUFFER_TOO_SMALL);
      /* add pt block to the given plaintext buffer */
      plaintext.appendArray(pt, (uint32_t)pt_len);
      this->updateDecCount++;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::decryptFinalize(OpenABEByteString& plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    if (this->init_dec_set && this->updateDecCount > 0) {
      /* finalize decryption */
      int pt_len = plaintext.size();
      int retValue =
          EVP_DecryptFinal_ex(this->ctx, plaintext.getInternalPtr(), &pt_len);
      /* clear memory before the check */
      EVP_CIPHER_CTX_free(this->ctx);
      this->ctx = NULL;
      this->updateDecCount = 0;
      // clear some buffers
      this->the_iv.fillBuffer(0, this->the_iv.size());
      this->aad.fillBuffer(0, this->aad.size());
      this->aad_set = false;
      this->init_dec_set = false;

      if (retValue > 0) {
        /* clear memory and return OpenABE_NOERROR */
        throw OpenABE_NOERROR;
      } else {
        /* tag verification failed. therefore, throw a decryption failed error
         */
        throw OpenABE_ERROR_DECRYPTION_FAILED;
      }
    } else {
      throw OpenABE_ERROR_INVALID_INPUT;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}
