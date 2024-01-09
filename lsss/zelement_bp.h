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
}

#include "zbytestring.h"
#include "zgroup.h"
#include "zobject.h"


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
  // std::shared_ptr<BPGroup> bgroup;

  G1() { g1_init(m_G1); g1_set_infty(m_G1); isInit = true; }
  G1(const G1 &w) { g1_init(m_G1); g1_copy(m_G1, w.m_G1); isInit = true; }

  ~G1() {
    if (isInit) {
      g1_free(m_G1);
      isInit = false;
    }
  }

  G1& operator*=(ZP k) {
    G1 tmp(*this);
    *this = tmp * k;
    return *this;
  }
  G1& operator+=(const G1 &x) {
    G1 tmp(*this);
    *this = tmp + x;
    return *this;
  }

  G1& operator=(const G1 &w) {
    g1_copy(m_G1, w.m_G1);
    return *this;
  }

  void setRandom() { if (isInit) g1_rand(this->m_G1); }
  void setGenerator() { if (isInit) g1_get_gen(this->m_G1); }

  int getSize() { return g1_size_bin(m_G1, 1); }

  uint8_t* getBytes(int *bufferSize);

  bool ismember() { return isInit && g1_is_valid(m_G1); }

  G1 operator*(ZP k) const { // scalar multiplication of G1 element
    G1 tmp;
    g1_mul(tmp.m_G1, m_G1, k.m_ZP);
    return tmp;
  }
  G1 operator-(const G1 &x) const {
    G1 tmp;
    g1_neg(tmp.m_G1, x.m_G1);
    return tmp;
  }
  G1 operator+(const G1 &x) const {
    G1 tmp;
    g1_add(tmp.m_G1, m_G1, x.m_G1);
    return tmp;
  }
  bool operator==(const G1 &x) const {
    return (g1_cmp(m_G1, x.m_G1) == RLC_EQ);
  }

  bool isEqual(ZObject *z) const {
    G1 *z1 = dynamic_cast<G1 *>(z);
    return (z1 != NULL) && (*z1 == *this);
  }

  G1* clone() const { return new G1(*this); }

  void serialize(OpenABEByteString &result);
  void deserialize(OpenABEByteString &input);
};


/// \class  G2
/// \brief  Class for G2 base field elements in ZML.
class G2 : public ZObject {
public:
  g2_t m_G2;
  bool isInit;
  // std::shared_ptr<BPGroup> bgroup;

  G2() { g2_init(m_G2); g2_set_infty(m_G2); isInit = true; }
  G2(const G2 &w) { g2_init(m_G2); g2_copy(m_G2, w.m_G2); isInit = true; }

  ~G2() {
    if (isInit) {
      g2_free(m_G2);
      isInit = false;
    }
  }

  G2& operator+=(const G2 &x) {
    G2 tmp(*this);
    *this = tmp + x;
    return *this;
  }
  G2& operator*=(ZP k) {
    G2 tmp(*this);
    *this = tmp * k;
    return *this;
  }

  G2& operator=(const G2 &w) {
    g2_copy(m_G2, w.m_G2);
    return *this;
  }

  void setRandom() { if (isInit) g2_rand(this->m_G2); }
  void setGenerator() { if (isInit) g2_get_gen(this->m_G2); }

  int getSize() { return g2_size_bin(m_G2, 1); }

  uint8_t* getBytes(int *bufferSize);

  bool ismember() { return isInit && g2_is_valid(m_G2); }
  G2 operator*(ZP k) const { // scalar multiplication of G2 element
    G2 tmp;
    g2_mul(tmp.m_G2, m_G2, k.m_ZP);
    return tmp;
  }
  G2 operator-(const G2 &x) const {
    G2 tmp;
    g2_neg(tmp.m_G2, x.m_G2);
    return tmp;
  }
  G2 operator+(const G2 &x) const {
    G2 tmp;
    g2_add(tmp.m_G2, m_G2, x.m_G2);
    return tmp;
  }
  bool operator==(const G2 &x) const {
    return (g2_cmp(m_G2, x.m_G2) == RLC_EQ);
  }

  bool isEqual(ZObject *z) const {
    G2 *z1 = dynamic_cast<G2 *>(z);
    return (z1 != NULL) && (*z1 == *this);
  }

  G2* clone() const { return new G2(*this); }

  void serialize(OpenABEByteString &result);
  void deserialize(OpenABEByteString &input);
};

/// \class  GT
/// \brief  Class for GT field elements in RELIC.
class GT : public ZObject {
public:
  gt_t m_GT;
  bool isInit;
  // std::shared_ptr<BPGroup> bgroup;

  GT() { gt_init(m_GT); gt_set_unity(m_GT); isInit = true; }
  GT(const GT &w) { gt_init(m_GT); gt_copy(m_GT, w.m_GT); isInit = true; }
  ~GT() { if (isInit) { gt_free(m_GT); isInit = false; } }


  void setIdentity() { if (isInit) gt_set_unity(m_GT); }
  void setRandom() { if (isInit) gt_rand(m_GT); }
  void setGenerator() { if (isInit) gt_get_gen(m_GT); }

  int getSize() { return gt_size_bin(m_GT, 1); }

  uint8_t* getBytes(int *bufferSize);

  bool isIdentity() { return isInit && gt_is_unity(m_GT); }
  bool ismember() { return isInit && gt_is_valid(m_GT); }

  GT exp(ZP k) {
    GT tmp;
    gt_exp(tmp.m_GT, this->m_GT, k.m_ZP);
    return tmp;
  }

  GT inverse() {
    GT tmp;
    gt_inv(tmp.m_GT, m_GT);
    return tmp;
  }

  GT operator*(const GT &x) {
    GT tmp; // tmp = x * this->m_GT
    gt_mul(tmp.m_GT, m_GT, x.m_GT);
    return tmp;
  }

  GT operator/(const GT &x) {
    GT tmp; // tmp = this->m_GT / x = this->m_GT * x^-1
    gt_inv(tmp.m_GT, x.m_GT);
    gt_mul(tmp.m_GT, m_GT, tmp.m_GT);
    return tmp;
  }

  GT& operator*=(const GT &x) {
    GT tmp(*this);
    *this = tmp * x;
    return *this;
  }

  GT& operator=(const GT &x) {
    gt_copy(m_GT, x.m_GT);
    return *this;
  }

  bool operator==(const GT& x) const {
    return (gt_cmp(m_GT, x.m_GT) == RLC_EQ);
  }

  bool isEqual(ZObject* z) const {
    GT *z1 = dynamic_cast<GT *>(z);
    return (z1 != NULL) && (*z1 == *this);
  }

  GT* clone() const { return new GT(*this); }

  void serialize(OpenABEByteString &result);
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
