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
/// \file   zcontainer.cpp
///
/// \brief  Generic container class for ciphertexts and keys.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABECONTAINER_CPP__

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

#include "abe/zcontainer.h"

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContainer class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContainer class.
 *
 */

OpenABEContainer::OpenABEContainer() : ZObject() { 
  this->group = make_shared<BPGroup>();
}

OpenABEContainer::OpenABEContainer(std::shared_ptr<BPGroup> group) : ZObject() {
  this->group = group;
}

/*!
 * Destructor for the OpenABEContainer class.
 *
 */

OpenABEContainer::~OpenABEContainer() {
  std::map<std::string, ZObject *>::iterator iter;
  for (iter = this->val.begin(); iter != this->val.end(); iter++) {
    delete iter->second;
  }
  this->val.clear();
}

/*!
 * Set component by name.
 *
 * @param Name of the ciphertext component
 * @param Object containing the component
 */

void OpenABEContainer::setComponent(const string &name, const ZObject *component) {
  ZObject *copy = component->clone();

  // release the previous value, if any (the clone is taken first so that
  // 'component' may alias the stored object)
  ZObject *&slot = this->val[name];
  delete slot;
  slot = copy;
}

/*!
 * Obtain a component based on the given key. Return a pointer to the object
 * or throw an error.
 *
 * @return Number of components in the ciphertext
 */

ZObject *OpenABEContainer::getComponent(const string &name) {
  ZObject *result = this->val[name];

  if (result == nullptr) {
    cerr << "OpenABEContainer::getComponent: missing '" << name << "'" << endl;
    throw OpenABE_ERROR_ELEMENT_NOT_FOUND;
  }

  return result;
}

OpenABE_ERROR
OpenABEContainer::deleteComponent(const string name) {
  map<string, ZObject *>::iterator iter1 = this->val.find(name);
  if (iter1 != this->val.end()) {
    delete iter1->second;
    this->val.erase(iter1);
    return OpenABE_NOERROR;
  }
  return OpenABE_ERROR_ELEMENT_NOT_FOUND;
}

/*!
 * Destructor for the OpenABEContainer class.
 *
 * @return Number of components in the ciphertext
 */

uint32_t OpenABEContainer::numComponents() { return this->val.size(); }

OpenABE_ERROR OpenABEContainer::zeroize() {
  return OpenABE_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Serialize the entire object.
 *
 * @return Byte vector containing the result
 */
void OpenABEContainer::serialize(OpenABEByteString &result) const {
  OpenABEByteString res, key, bytes;
  std::map<std::string, ZObject *>::const_iterator it;
  for (it = this->val.begin(); it != this->val.end(); ++it) {
    it->second->serialize(bytes);
    key = it->first;
    result.smartPack(key);
    result.smartPack(bytes);
  }
}

void OpenABEContainer::deserializeElement(std::string key, OpenABEByteString &value) {
  if (value.size() == 0) {
    throw OpenABE_ERROR_INVALID_INPUT;
  }
  uint8_t type = value.at(0);

  if (type == OpenABE_ELEMENT_INT) {
    unique_ptr<OpenABEUInteger> i(new OpenABEUInteger(0));
    i->deserialize(value);
    this->setComponent(key, i.get());
  } else if (type >= OpenABE_ELEMENT_ZP && type <= OpenABE_ELEMENT_GT) {
    ASSERT(this->group != nullptr, OpenABE_ERROR_INVALID_GROUP_PARAMS);
    std::shared_ptr<BPGroup> bp = dynamic_pointer_cast<BPGroup>(group);
    ASSERT(bp != nullptr, OpenABE_ERROR_INVALID_GROUP_PARAMS);
    if (type == OpenABE_ELEMENT_ZP) {
      unique_ptr<ZP> s(new ZP);
      s->setOrder(bp->order);
      s->deserialize(value);
      this->setComponent(key, s.get());
    } else if (type == OpenABE_ELEMENT_G1) {
      unique_ptr<G1> g(new G1());
      g->deserialize(value);
      this->setComponent(key, g.get());
    } else if (type == OpenABE_ELEMENT_G2) {
      unique_ptr<G2> g(new G2());
      g->deserialize(value);
      this->setComponent(key, g.get());
    } else {
      unique_ptr<GT> g(new GT());
      g->deserialize(value);
      this->setComponent(key, g.get());
    }
  } else if (type == OpenABE_ELEMENT_BYTESTRING) {
    unique_ptr<OpenABEByteString> b(new OpenABEByteString);
    b->deserialize(value);
    this->setComponent(key, b.get());
  } else if (type == OpenABE_ELEMENT_POLICY) {
    const string b = value.toString();
    unique_ptr<OpenABEPolicy> p = createPolicyTree(b);
    if (p == nullptr) {
      throw OpenABE_ERROR_INVALID_POLICY_TREE;
    }
    this->setComponent(key, p.get());
  } else if (type == OpenABE_ELEMENT_ATTRIBUTES) {
    const string b = value.toString();
    unique_ptr<OpenABEAttributeList> a = createAttributeList(b);
    if (a == nullptr) {
      throw OpenABE_ERROR_INVALID_ATTRIBUTE_LIST;
    }
    this->setComponent(key, a.get());
  } else if (type == OpenABE_ELEMENT_ZP_t || type == OpenABE_ELEMENT_G_t) {
    ASSERT(this->group != nullptr, OpenABE_ERROR_INVALID_GROUP_PARAMS);
    std::shared_ptr<BPGroup> ec = dynamic_pointer_cast<BPGroup>(group);
    ASSERT(ec != nullptr, OpenABE_ERROR_INVALID_GROUP_PARAMS);
  } else { 
    cout << "Invalid Input type: " << type << endl;
    throw OpenABE_INVALID_INPUT_TYPE;
  }

  return;
}

void OpenABEContainer::deserialize(OpenABEByteString &blob) {
  OpenABEByteString result, key, value;
  result = blob;
  size_t index = 0;

  do {
    key = result.smartUnpack(&index);
    value = result.smartUnpack(&index);
    this->deserializeElement(key.toString(), value);
  } while (index < result.size());
  return;
}

void OpenABEContainer::deserialize(string &blob) {
  OpenABEByteString result;
  result = blob;
  return this->deserialize(result);
}

std::vector<std::string> OpenABEContainer::getKeys() {
  std::vector<std::string> keyList;
  std::map<std::string, ZObject *>::iterator iter;
  for (iter = this->val.begin(); iter != this->val.end(); iter++) {
    keyList.push_back(iter->first);
  }

  return keyList;
}

bool operator==(const OpenABEContainer &c1, const OpenABEContainer &c2) {
  // std::map iterates in key order: walk both maps in lockstep.
  if (c1.val.size() != c2.val.size()) {
    return false;
  }
  auto it1 = c1.val.begin();
  auto it2 = c2.val.begin();
  for (; it1 != c1.val.end(); ++it1, ++it2) {
    if (it1->first != it2->first) {
      return false;
    }
    const ZObject *lhs = it1->second;
    ZObject *rhs = it2->second;
    if (lhs == nullptr || rhs == nullptr || !lhs->isEqual(rhs)) {
      return false;
    }
  }
  return true;
}
