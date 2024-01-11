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
/// \file   zobject.h
///
/// \brief  Class definition for the abstract OpenABE object.
///         This is subclassed by all OpenABE specific structures.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef openabe_ZObject_h
#define openabe_ZObject_h

#include <cstdlib>
#include <string>
#include <vector>
#include <stdexcept>


class OpenABEByteString;

class ZObject {
public:
  ZObject();
  virtual ~ZObject();
    
  void addRef();
  void deRef();
  uint32_t getRefCount() { return this->refCount; }
  virtual ZObject& operator=(const ZObject &rhs) { return *this; }
  virtual ZObject* clone() const { return nullptr; }
  virtual void serialize(OpenABEByteString &result) const { throw std::runtime_error("Not implemented"); }
  virtual bool isEqual(ZObject* z) const { return false; }

protected:
  uint32_t refCount;
};

// zeroization
void  OpenABEZeroize(void *b, size_t b_len);
// base-64 encoding functions
std::string Base64Encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string Base64Decode(std::string const& encoded_string);
bool is_base64(unsigned char c);

//ZObject *deserializeObject(OpenABEByteString);


#endif
