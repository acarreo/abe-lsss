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
/// \file   zciphertext.cpp
///
/// \brief  Class implementation for storing OpenABE ciphertexts.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABECONTAINER_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

#include <abe_lsss.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABECiphertext class
 ********************************************************************************/

/*!
 * Constructor for the OpenABECiphertext class.
 *
 */
OpenABECiphertext::OpenABECiphertext() : OpenABEContainer() {
  this->algorithmID = 0; // OpenABE_SCHEME_NONE 
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  this->uid.fillBuffer(0, UID_LEN);
  this->uid_set_extern = false;
}

OpenABECiphertext::OpenABECiphertext(std::shared_ptr<BPGroup> group)
    : OpenABEContainer(group) {
  this->algorithmID = 0; // OpenABE_SCHEME_NONE;
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  this->uid.fillBuffer(0, UID_LEN);
  this->uid_set_extern = false;
}

OpenABECiphertext::OpenABECiphertext(const OpenABEByteString &uid) : OpenABEContainer() {
  this->algorithmID = 0; // OpenABE_SCHEME_NONE;
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  if (uid.size() >= UID_LEN) {
    this->uid = uid;
    this->uid_set_extern = true;
  } else {
    // failed to set externally, so one will be generated randomly
    this->uid.fillBuffer(0, UID_LEN);
    this->uid_set_extern = false;
  }
}

/*!
 * Destructor for the OpenABECiphertext class.
 *
 */
OpenABECiphertext::~OpenABECiphertext() {}

/*!
 * Export routine for the OpenABECiphertext class (includes header and container elements).
 *
 */
void OpenABECiphertext::exportToBytes(OpenABEByteString &output) {
  OpenABEByteString ciphertextHeader, ciphertextBytes;
  // libVersion || AlgID || uid || id
  this->getHeader(ciphertextHeader);
  // serialize the ciphertext elements
  this->serialize(ciphertextBytes);

  // cout << "------> CiphertextBytes serialized" << endl;
  // OpenABEByteString tempDebug;
  // tempDebug.fillBuffer(0, SHA256_LEN);
  // _hash_to_bytes_(tempDebug.getInternalPtr(), ciphertextBytes.data(), ciphertextBytes.size());
  // cout << tempDebug.toHex() << endl;

  // first pack the key header
  // then pack the key bytes
  output.clear();
  output.smartPack(ciphertextHeader);
  output.smartPack(ciphertextBytes);
  return;
}

/*!
 * Import routine for the OpenABECiphertext class (includes header and container elements).
 *
 */
void OpenABECiphertext::loadFromBytes(OpenABEByteString &input) {
  size_t hdrLen = UID_LEN + 2*sizeof(uint8_t); // 1 byte for library version, 1 byte for algorithm ID
  if (input.size() < hdrLen) {
    cerr << "------> Invalid input size for OpenABECiphertext " << input.size() << endl;
    throw OpenABE_ERROR_INVALID_INPUT;
  }

  OpenABEByteString ciphertextHeader, ciphertextBytes;
  size_t index = 0;
  // convert to OpenABEByteStrings
  ciphertextHeader = input.smartUnpack(&index);

  if (ciphertextHeader.size() == hdrLen) {
    // assert that libID matches current libID
    ASSERT(ciphertextHeader.at(0) <= OpenABE_LIBRARY_VERSION, OpenABE_ERROR_INVALID_LIBVERSION);
    this->libraryVersion = ciphertextHeader.at(0);

    // compose portions of header
    this->algorithmID = OpenABE_getSchemeID(ciphertextHeader.at(1));
    this->uid = ciphertextHeader.getSubset(2, UID_LEN);

    // fetch remaining ciphertext bytes
    ciphertextBytes = input.smartUnpack(&index);
    ASSERT(ciphertextBytes.size() > 0, OpenABE_ERROR_INVALID_CIPHERTEXT_BODY);
    this->deserialize(ciphertextBytes);

    // cout << "------> CiphertextBytes deserialized" << endl;
    // OpenABEByteString tempDebug;
    // tempDebug.fillBuffer(0, SHA256_LEN);
    // _hash_to_bytes_(tempDebug.getInternalPtr(), ciphertextBytes.data(), ciphertextBytes.size());
    // cout << tempDebug.toHex() << endl;
  } else {
    cerr << "------> Ciphertext header size: " << ciphertextHeader.size() << endl;
    throw OpenABE_ERROR_INVALID_CIPHERTEXT_HEADER;
  }
}

/*!
 * Export routine for the OpenABECiphertext class (sames as before but without header).
 *
 */
void OpenABECiphertext::exportToBytesWithoutHeader(OpenABEByteString &output) {
  OpenABEByteString ciphertextBytes;
  // serialize the ciphertext elements
  this->serialize(ciphertextBytes);
  // first pack the key header
  // then pack the key bytes
  output.clear();
  output.smartPack(ciphertextBytes);
  return;
}

/*!
 * Import routine for the OpenABECiphertext class (same as before but without header).
 *
 */
void OpenABECiphertext::loadFromBytesWithoutHeader(OpenABEByteString &input) {
  OpenABEByteString ciphertextBytes;
  size_t index = 0;

  ciphertextBytes = input.smartUnpack(&index);
  ASSERT(ciphertextBytes.size() > 0, OpenABE_ERROR_INVALID_CIPHERTEXT_BODY);
  // deserialize bytes into this container
  this->deserialize(ciphertextBytes);
  return;
}

/*!
 * Obtain the serialized form of the OpenABEKey header.
 *
 */

void OpenABECiphertext::setHeader(OpenABE_SCHEME scheme_type, OpenABEByteString &uid) {
  /* set the header of the ciphertext */
  this->algorithmID = scheme_type;
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  this->uid.clear();
  this->uid = uid;
}

/*!
 * Obtain the serialized form of the OpenABEKey header.
 *
 */
void OpenABECiphertext::getHeader(OpenABEByteString &header) {
  header.clear();
  header.push_back(this->libraryVersion);
  header.push_back(this->algorithmID);
  header += this->uid;
}
