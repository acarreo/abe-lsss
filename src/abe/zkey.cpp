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
/// \file   zkey.cpp
///
/// \brief  Class implementation for storing/managing all types of OpenABE keys.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __ZKEY_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

#include "abe/zkey.h"
#include <abe_lsss.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEKey class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEKey class.
 *
 */

OpenABEKey::OpenABEKey() : OpenABEContainer() {
  this->algorithmID = OpenABE_SCHEME_NONE;
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  this->ID = "";
  this->key_type = OpenABEKEY_NONE;
  this->isPrivate = false;
}

/*!
 * Constructor for the OpenABEKey class.
 *
 */

OpenABEKey::OpenABEKey(uint8_t algorithmID, const string ID,
               OpenABEByteString *uid)
    : OpenABEContainer() {
  // the identifier of the scheme in OpenABE
  this->algorithmID = algorithmID;
  // current library version
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  if (uid != NULL && uid->size() == UID_LEN) {
    // random identifier that is public but useful for deriving keys
    this->uid = *uid;
  } else {
    // if 'uid' input is NULL, then just generate an id internally
    getRandomBytes(this->uid, UID_LEN);
  }
  // can be any string to represent the key holder's identification
  this->ID = ID;
  this->key_type = OpenABE_KeyTypeFromAlgorithmID(algorithmID);
  this->isPrivate = false;
}

/*!
 * Destructor for the OpenABEKey class.
 *
 */

OpenABEKey::~OpenABEKey() {}

/*!
 * Obtain the serialized form of the OpenABEKey header.
 *
 */

void OpenABEKey::getHeader(OpenABEByteString &header) const {
  header.clear();
  header.push_back(this->libraryVersion);
  header.push_back(this->algorithmID);
  header += this->uid;
  header += this->ID;
}

OpenABE_ERROR
OpenABEKey::exportKeyToBytes(OpenABEByteString &output) const {
  output.clear();
  OpenABEByteString keyHeader, keyBytes;
  // libVersion || AlgID || uid || id
  this->getHeader(keyHeader);
  // serialize the key structure
  this->serialize(keyBytes);
  // first pack the key header
  // then pack the key bytes
  output.pack(keyHeader.getInternalPtr(), keyHeader.size());
  output.pack(keyBytes.getInternalPtr(), keyBytes.size());
  // clear the contents of the intermediate buffers
  keyHeader.clear();
  keyBytes.clear();

  return OpenABE_NOERROR;
}

OpenABE_ERROR
OpenABEKey::loadKeyFromBytes(OpenABEByteString &input) {
  this->deserialize(input);
  return OpenABE_NOERROR;
}

void getRandomBytes(uint8_t *buf, size_t buf_len) {
  rand_bytes(buf, buf_len);
}

void getRandomBytes(OpenABEByteString &buf, size_t buf_len) {
  buf.clear();
  buf.fillBuffer(0, buf_len);
  rand_bytes(buf.getInternalPtr(), buf_len);
}

void generateSymmetricKey(std::string& key, uint32_t keyLen) {
  OpenABEByteString key_buf;
  getRandomBytes(key_buf, (int) keyLen);
  key = key_buf.toString();
}
