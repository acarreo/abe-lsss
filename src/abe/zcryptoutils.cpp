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
/// \file   zcryptoutils.cpp
///
/// \brief  Miscellaneous cryptographic utilities.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABECRYPTOUTILS_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>

#include "abe/zcryptoutils.h"
#include "abe/zkdf.h"

using namespace std;

/********************************************************************************
 * Global utility routines
 ********************************************************************************/

/*!
 * Utility for hashing a group element into a string.
 *
 */

bool OpenABEUtilsHashToString(GT &input, uint32_t keyLen, OpenABEByteString &result) {
  stringstream concatResult;
  OpenABEByteString serializedResult;
  uint32_t numBytes = 0;

  result.clear();
  input.serialize(serializedResult);

  for (uint32_t i = 0; numBytes < keyLen; i++, numBytes += RLC_MD_LEN) {
    concatResult.clear();
    concatResult << numBytes << serializedResult << serializedResult.size();
    uint8_t digest[RLC_MD_LEN];
    _hash_to_bytes_(digest, (uint8_t *)(concatResult.str().c_str()),
           concatResult.str().size());
    result.appendArray(digest, RLC_MD_LEN);
  }

  return true;
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
