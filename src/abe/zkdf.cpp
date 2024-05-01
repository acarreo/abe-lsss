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
/// \file   zkdf.cpp
///
/// \brief  Implementation for key derivation functions.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "abe/zkdf.h"

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEKDF class
 ********************************************************************************/
// namespace oabe {

/*!
 * Constructor for the OpenABEKDF class.
 *
 */

OpenABEKDF::OpenABEKDF(uint8_t hashPrefix, uint32_t hashLen, uint32_t maxInputLen)
    : ZObject() {
  // select a hash prefix for KDFs
  this->hashPrefix = hashPrefix;
  // bitlength of target hash function, H
  this->hashLen = hashLen;
  // max bitlength of input to hash function
  this->maxInputLen = maxInputLen;
}

/*!
 * Destructor for the OpenABEKDF class.
 *
 */

OpenABEKDF::~OpenABEKDF() {}

/*!
 * A concatenated KDF from NIST SP800-56A - Section 5.8.1 for deriving keys.
 * Returns the derived key of size keydataLenBytes.
 *
 * @param[in]   the shared key represented as a bytestring.
 * @param[in]   the number of bits for the returned key.
 * @param[in]   auxiliary information that is provided as input into the KDF.
 * @return  A OpenABEByteString object that contains the derived key.
 */

OpenABEByteString OpenABEKDF::DeriveKey(OpenABEByteString &Z, uint32_t keyBitLen,
                                OpenABEByteString &metadata) {
  // compute number of hash blocks needed (round up)
  OpenABEByteString buffer;
  uint32_t count = 1;

  // ceiling of keydataLen / hashLen (bitwise)
  size_t reps_len = (size_t)ceil(((double)keyBitLen) / this->hashLen);
  if (reps_len > OpenABE_MAX_KDF_BITLENGTH) {
    throw OpenABE_ERROR_INVALID_LENGTH;
  }

  // buffer = counter || hashPrefix || Z || Metadata
  buffer.setFirstBytes(count);
  buffer.push_back(this->hashPrefix);
  buffer.appendArray(Z.data(), Z.size());
  buffer.appendArray(metadata.data(), metadata.size());

  if (buffer.size() > this->maxInputLen) {
    throw OpenABE_ERROR_INVALID_LENGTH;
  }

  // set the hash_len
  int hash_len = reps_len * this->hashLen;
  uint8_t hash[hash_len + 1];
  memset(hash, 0, hash_len + 1);

  uint8_t *hash_ptr = hash;
  for (size_t i = 0; i < reps_len; i++) {
    // H(count++ || prefix || Z || Metadata)
    _hash_to_bytes_(hash_ptr, buffer.data(), buffer.size());
    count++;
    buffer.setFirstBytes(count);
    hash_ptr += this->hashLen; // move ptr by hashLen bytes
  }

  uint32_t keydataBytes = keyBitLen / 8;
  OpenABEByteString keyMaterial;
  keyMaterial.appendArray(hash, keydataBytes);
  return keyMaterial;
}


/********************************************************************************
 * Implementation of the ComputeKDF2 wrapper
 ********************************************************************************/

/*!
 *
 * @param[in]   a key.
 * @param[in]   the number of bytes for the returned key.
 * @return      A OpenABEByteString object that contains the derived key.
 */
OpenABEByteString OpenABEKDF::ComputeKDF2(OpenABEByteString &key, uint32_t keydataLenBytes)
{
  ASSERT(key.size() > 0, OpenABE_ERROR_INVALID_INPUT);
  ASSERT(keydataLenBytes > 0, OpenABE_ERROR_INVALID_INPUT);

  /* cheap allocation for keydataLenBytes */
  OpenABEByteString output_key;
  output_key.fillBuffer(0, keydataLenBytes);

  md_kdf(output_key.getInternalPtr(), keydataLenBytes, key.data(), key.size());

  return output_key;
}

OpenABEByteString OpenABEKDF::ComputeHKDF(OpenABEByteString& key,
                  OpenABEByteString& salt, OpenABEByteString& info, size_t key_len)
{
  uint8_t prk[RLC_MD_LEN];
  uint8_t h_salt[RLC_MD_LEN];
  uint8_t tmp_okm[RLC_MD_LEN];

  if (salt.size() == 0) {
    salt.fillBuffer(0, RLC_MD_LEN);
  }

  // extract
  md_map(h_salt, salt.data(), salt.size());
  md_hmac(prk, h_salt, RLC_MD_LEN, key.data(), key.size());

  // expand
  int i = 0;
  OpenABEByteString tmp, tmp_ii;
  OpenABEByteString output_key;
  while (output_key.size() < key_len) {
    tmp_ii = tmp + info;
    tmp_ii.pack8bits((uint8_t)++i);
    md_hmac(tmp_okm, tmp_ii.data(), tmp_ii.size(), prk, RLC_MD_LEN);
    tmp.appendArray(tmp_okm, RLC_MD_LEN);
    output_key += tmp;
  }
  output_key.resize(key_len);

  return output_key;
}

string OpenABEHashKey(const string attr_key) {
  OpenABEByteString hex_digest;
  string hash;
  if (attr_key.size() > 16) {
    uint8_t digest[RLC_MD_LEN];
    _hash_to_bytes_(digest, (uint8_t *)(attr_key.c_str()), attr_key.size());
    hash = string((char *)digest, RLC_MD_LEN);
    hex_digest += hash.substr(0,8);
    return hex_digest.toLowerHex();
  }
  return attr_key;
}
