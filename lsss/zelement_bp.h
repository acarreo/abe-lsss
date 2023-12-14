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
class BPGroup : public ZGroup {
public:
  bignum_t     order;

  BPGroup(OpenABECurveID id);
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
  std::shared_ptr<BPGroup> bgroup;

  G1(std::shared_ptr<BPGroup> bgroup) : bgroup(bgroup) {
    g1_init(m_G1);
    g1_set_infty(m_G1);
    isInit = true;
  }

  G1(const G1 &w) : bgroup(w.bgroup) {
    g1_init(m_G1);
    g1_copy(m_G1, w.m_G1);
    isInit = true;
  }

  ~G1() {
    if (isInit) {
      g1_free(m_G1);
      isInit = false;
    }
  }

  G1& operator*=(const G1 &x) {
    G1 tmp(*this);
    *this = tmp * x;
    return *this;
  }

  G1& operator=(const G1 &w) {
    bgroup = w.bgroup;
    g1_copy(m_G1, w.m_G1);
    return *this;
  }

  void setRandom() { if (isInit) g1_rand(this->m_G1); }
  bool ismember() { return isInit && g1_is_valid(m_G1); }
  G1 exp(ZP) {
    G1 tmp(this->bgroup);
    g1_mul(tmp.m_G1, this->m_G1, ZP.m_ZP);
    return tmp;
  }
  friend G1 operator-(const G1 &x) {
    G1 tmp(x.bgroup);
    g1_neg(tmp.m_G1, x.m_G1);
    return tmp;
  }
  friend G1 operator*(const G1 &x,const G1 &y) {
    G1 tmp(x.bgroup);
    g1_add(tmp.m_G1, x.m_G1, y.m_G1);
    return tmp;
  }
  friend bool operator==(const G1 &x, const G1 &y) {
    return (g1_cmp(x.m_G1, y.m_G1) == CMP_EQ);
  }

  bool isEqual(ZObject *z) const {
    G1 *z1 = dynamic_cast<G1 *>(z);
    return (z1 != NULL) && (*z1 == *this);
  }
};


#if 0
/// \class  GT
/// \brief  Class for GT field elements in RELIC.
class GT : public ZObject {
public:
  gt_t m_GT;
  bool isInit;
  std::shared_ptr<BPGroup> bgroup;

  GT(std::shared_ptr<BPGroup> bgroup);
  GT(const GT &w);
  ~GT();
  GT& operator*=(const GT &x);
  GT& operator=(const GT &x);

  void enableCompression() { shouldCompress_ = true; };
  void disableCompression() { shouldCompress_ = false; };
  //void setRandom(OpenABERNG *rng);
  void setIdentity();
  bool isInfinity();
  bool ismember(bignum_t);
  GT exp(ZP);

  friend GT operator-(const GT&);
  friend GT operator/(const GT&,const GT&);
  friend GT operator*(const GT&,const GT&);
  friend std::ostream& operator<<(std::ostream& s, const GT&);
  friend bool operator==(const GT& x, const GT& y);
  friend bool operator!=(const GT& x, const GT& y);

  GT* clone() const { return new GT(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;

private:
  bool shouldCompress_;
};
#endif

/// \typedef    OpenABEElementList
/// \brief      Vector or list of elements
typedef std::vector<ZP> OpenABEElementList;

/// \typedef    OpenABEElementListIterator
/// \brief      Iterator for an OpenABEElementList of rows in an LSSS
typedef OpenABEElementList::iterator OpenABEElementListIterator;

#endif	// __ZELEMENT_BP_H__
