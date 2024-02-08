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
/// \file   zelement_bp.h
///
/// \brief  Class definition for a group element.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZELEMENT_BP_H__
#define __ZELEMENT_BP_H__

#include <list>
#include <memory>

extern "C" {
  #include "zelement.h"
  #include <relic.h>
}

#include "zbytestring.h"
#include "zobject.h"


#define G1_SIZE_BIN             ((RLC_PC_BYTES) * 2 + 1)
#define G2_SIZE_BIN             ((RLC_PC_BYTES) * 4 + 1)

#define G1_SIZE_BIN_COMPRESSED  ((RLC_PC_BYTES) + 1)
#define G2_SIZE_BIN_COMPRESSED  ((RLC_PC_BYTES) * 2 + 1)

class OpenABEByteString;

void ro_error(void);

// retrieve the group field of the BPGroup class
#define GET_BP_GROUP(g)    g->group

/// \class  ECGroup
/// \brief  Wrapper for managing elliptic curve groups
class BPGroup {
public:
  bignum_t     order;

  BPGroup();
  ~BPGroup();

  void getGroupOrder(bignum_t o);
};


/// \class  ZP
/// \brief  Class for ZP elements in ZML.
class ZP : public ZObject {
public:
  bignum_t m_ZP;
  bignum_t order;
  bool isInit, isOrderSet;
  ZP();
  ZP(uint32_t);
  ZP(char*, bignum_t);
  ZP(uint8_t*, uint32_t, bignum_t);
  ZP(bignum_t y);
  ZP(const ZP& w);

  ~ZP();
  ZP& operator+=(const ZP& x);
  ZP& operator*=(const ZP& x);
  ZP& operator=(const ZP& w);

  std::string getBytesAsString();
  OpenABEByteString getByteString() const;
  void getLengthAndByteString(OpenABEByteString &z) const;
  void setOrder(const bignum_t o);
  void setRandom(bignum_t o);

  void setFrom(ZP&, uint32_t);
  bool ismember();
  void multInverse();

  friend ZP power(const ZP&, unsigned int);
  friend ZP power(const ZP&, const ZP&);
  friend ZP operator-(const ZP&);
  friend ZP operator-(const ZP&,const ZP&);
  friend ZP operator+(const ZP&,const ZP&);
  friend ZP operator*(const ZP&,const ZP&);
  friend ZP operator/(const ZP&,const ZP&);
  friend ZP operator<<(const ZP&, int);
  friend ZP operator>>(const ZP&, int);

  friend std::ostream& operator<<(std::ostream&, const ZP&);
  friend bool operator<(const ZP& x, const ZP& y);
  friend bool operator<=(const ZP& x, const ZP& y);
  friend bool operator>(const ZP& x, const ZP& y);
  friend bool operator>=(const ZP& x, const ZP& y);
  friend bool operator==(const ZP& x, const ZP& y);
  friend bool operator!=(const ZP& x, const ZP& y);

  ZP*    clone() const { return new ZP(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;
};

/// \class  G1
/// \brief  Class for G1 base field elements in ZML.
class G1 : public ZObject {
public:
  g1_t m_G1;
  bool isInit;

  G1();
  G1(const G1 &w);
  G1(const g1_t &w);

  ~G1();

  G1& operator*=(const ZP k);
  G1& operator+=(const G1 &x);
  G1& operator=(const G1 &w);

  void setRandom();
  void setGenerator();
  uint8_t* getBytes(int *bufferSize);

  G1 operator*(const ZP k) const;
  G1 operator-(const G1 &x) const;
  G1 operator+(const G1 &x) const;
  bool operator==(const G1 &x) const;

  int getSize() const;
  bool ismember() const;
  bool isEqual(ZObject *z) const;
  G1* clone() const;

  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
};


/// \class  G2
/// \brief  Class for G2 base field elements in ZML.
class G2 : public ZObject {
public:
  g2_t m_G2;
  bool isInit;

  G2();
  G2(const G2 &w);
  G2(const g2_t &w);

  ~G2();

  G2& operator+=(const G2 &x);
  G2& operator*=(const ZP k);
  G2& operator=(const G2 &w);

  void setRandom();
  void setGenerator();

  uint8_t* getBytes(int *bufferSize);

  G2 operator*(const ZP k) const;
  G2 operator-(const G2 &x) const;
  G2 operator+(const G2 &x) const;
  bool operator==(const G2 &x) const;

  int getSize() const;
  bool ismember() const;
  bool isEqual(ZObject *z) const;
  G2* clone() const;

  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
};

/// \class  GT
/// \brief  Class for GT field elements in RELIC.
class GT : public ZObject {
public:
  gt_t m_GT;
  bool isInit;

  GT();
  GT(const GT &w);

  ~GT();

  void setIdentity();
  void setRandom();
  void setGenerator();

  uint8_t* getBytes(int *bufferSize);

  GT exp(const ZP k) const;
  GT inverse() const;

  GT& operator*=(const GT &x);
  GT& operator=(const GT &x);

  GT operator*(const GT &x) const;
  GT operator/(const GT &x) const;
  bool operator==(const GT& x) const;

  int getSize();
  bool isIdentity() const;
  bool ismember() const;
  bool isEqual(ZObject* z) const;
  GT* clone() const;

  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
};

GT pairing(const G1 &x, const G2 &y);

/// \typedef    OpenABEElementList
/// \brief      Vector or list of elements
typedef std::vector<ZP> OpenABEElementList;

/// \typedef    OpenABEElementListIterator
/// \brief      Iterator for an OpenABEElementList of rows in an LSSS
typedef OpenABEElementList::iterator OpenABEElementListIterator;

#endif	// __ZELEMENT_BP_H__
