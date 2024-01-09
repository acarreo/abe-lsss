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
/// \file   zelement_bp.cpp
///
/// \brief  Class implementation for OpenABE group elements.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <list>
#include <memory>

#include "zbytestring.h"
#include "zgroup.h"
#include "zobject.h"
#include "zelement_bp.h"

using namespace std;

void ro_error(void) {
  cout << "Writing to read only object." << endl;
  exit(0);
}

/********************************************************************************
 * Implementation of the Group class
 ********************************************************************************/

BPGroup::BPGroup()
{
  zmbignum_init(&order);
  ep_curve_get_ord(order);
}

BPGroup::~BPGroup() { zmbignum_free(order); }

void BPGroup::getGroupOrder(bignum_t o) { zmbignum_copy(o, order); }

/********************************************************************************
 * Implementation of the ZP class
 ********************************************************************************/

// Begin ZP-specific classes

ZP::ZP()
{
  zmbignum_init(&this->m_ZP);
  zmbignum_init(&this->order);
  isOrderSet = false;
  isInit = true;
}

ZP::ZP(uint32_t x)
{
  zmbignum_init(&this->m_ZP);
  zmbignum_init(&this->order);
  zmbignum_setuint(this->m_ZP, x);
  isOrderSet = false;
  isInit = true;
}

ZP::ZP(char *hex_str, bignum_t o)
{
  zmbignum_init(&m_ZP);
  zmbignum_init(&order);
  zmbignum_copy(order, o);
  zmbignum_fromHex(m_ZP, (const char *)hex_str, strlen(hex_str));
  isOrderSet = true;
  isInit = true;
}

ZP::ZP(uint8_t *bstr, uint32_t bstr_len, bignum_t o)
{
  zmbignum_init(&m_ZP);
  zmbignum_init(&order);
  zmbignum_copy(order, o);
  zmbignum_fromBin(m_ZP, bstr, bstr_len);
  zmbignum_mod(m_ZP, order);
  isOrderSet = true;
  isInit = true;
}

ZP::ZP(bignum_t y)
{
  zmbignum_init(&m_ZP);
  zmbignum_copy(m_ZP, y);
  zmbignum_init(&order);
  isOrderSet = false;
  isInit = true;
}

ZP::ZP(const ZP &w)
{
  zmbignum_init(&this->m_ZP);
  zmbignum_copy(this->m_ZP, w.m_ZP);
  zmbignum_init(&this->order);
  zmbignum_copy(this->order, w.order);
  isInit = w.isInit;
  isOrderSet = w.isOrderSet;
}

ZP::~ZP() {
  zmbignum_free(m_ZP);
  zmbignum_free(order);
}

ZP &ZP::operator+=(const ZP &x) {
  ZP r(*this);
  *this = r + x;
  return *this;
}

ZP &ZP::operator*=(const ZP &x) {
  ZP r(*this);
  *this = r * x;
  return *this;
}

ZP &ZP::operator=(const ZP &w) {
  if (isInit) {
    zmbignum_copy(m_ZP, w.m_ZP);
    zmbignum_copy(order, w.order);
    isOrderSet = w.isOrderSet;
  }
  else ro_error();
  return *this;
}

ZP operator+(const ZP &x, const ZP &y) {
  ZP zr;
  if (x.isOrderSet) zr.setOrder(x.order);
  else zr.setOrder(y.order);

  zmbignum_add(zr.m_ZP, x.m_ZP, y.m_ZP, zr.order);
  return zr;
}

ZP operator-(const ZP &x, const ZP &y) {
  ZP zr;
  if (x.isOrderSet) zr.setOrder(x.order);
  else zr.setOrder(y.order);

  zmbignum_sub_order(zr.m_ZP, x.m_ZP, y.m_ZP, zr.order);
  return zr;
}

ZP operator-(const ZP &x) {
  ZP zr = x;
  zmbignum_negate(zr.m_ZP, zr.order);
  return zr;
}

ZP operator*(const ZP &x, const ZP &y) {
  ZP zr;
  if (x.isOrderSet) zr.setOrder(x.order);
  else zr.setOrder(y.order);

  zmbignum_mul(zr.m_ZP, x.m_ZP, y.m_ZP, zr.order);
  return zr;
}

void ZP::multInverse() {
  if (this->isInit && this->isOrderSet)
    zmbignum_mod_inv(this->m_ZP, this->m_ZP, this->order);
}

ZP operator/(const ZP &x, const ZP &y)
{
  ZP c;
  if (zmbignum_is_zero(y.m_ZP)) {
    cout << "Divide by zero error!" << endl;
    exit(-1);
  }

  ZP r;
  if (x.isOrderSet) r.setOrder(x.order);
  else r.setOrder(y.order);

  zmbignum_div(r.m_ZP, x.m_ZP, y.m_ZP, r.order);
  return r;
}

ZP power(const ZP &x, unsigned int r)
{
  ZP zr;
  zr.setOrder(x.order);

  bignum_t p;
  zmbignum_init(&p);
  zmbignum_setuint(p, r);
  zmbignum_exp(zr.m_ZP, x.m_ZP, p, zr.order);
  zmbignum_free(p);
  return zr;
}

ZP power(const ZP &x, const ZP &r) {
  ZP zr;
  if (x.isOrderSet) zr.setOrder(x.order);
  else zr.setOrder(r.order);

  zmbignum_exp(zr.m_ZP, x.m_ZP, r.m_ZP, zr.order);
  return zr;
}

bool ZP::ismember(void) {
  return (zmbignum_cmp(m_ZP, order) == BN_CMP_LT) &&
         (zmbignum_sign(m_ZP) == RLC_POS);
}

void ZP::setOrder(const bignum_t o) {
  if (!isOrderSet) {
    zmbignum_copy(order, o);
    isOrderSet = true;
  }
}

void ZP::setRandom(bignum_t o) {
  if (!this->isOrderSet) {
    this->isOrderSet = true;
    zmbignum_copy(this->order, o);
  }
  zmbignum_rand(this->m_ZP, this->order);
}

void ZP::setFrom(ZP &z, uint32_t index) {
  zmbignum_copy(this->m_ZP, z.m_ZP);
  *this = *this + index;
}

ostream &operator<<(ostream &os, const ZP &zr)
{
  int len = 0;
  char *str = NULL;
  len = bn_size_str(zr.m_ZP, 10);
  str = (char *)malloc(len+1);
  bn_write_str(str, len, zr.m_ZP, 10);

  string s0 = string(str, len - 1);
  zmbignum_safe_free(str);
  os << s0 << " (orderSet: " << (zr.isOrderSet ? "true)" : "false)");
  return os;
}

bool operator<(const ZP &x, const ZP &y) {
  return (zmbignum_cmp(x.m_ZP, y.m_ZP) == BN_CMP_LT);
}

bool operator<=(const ZP &x, const ZP &y) {
  return (zmbignum_cmp(x.m_ZP, y.m_ZP) <= BN_CMP_EQ);
}

bool operator>(const ZP &x, const ZP &y) {
  return (zmbignum_cmp(x.m_ZP, y.m_ZP) == BN_CMP_GT);
}

bool operator>=(const ZP &x, const ZP &y) {
  return (zmbignum_cmp(x.m_ZP, y.m_ZP) >= BN_CMP_EQ);
}

bool operator==(const ZP &x, const ZP &y) {
  return (zmbignum_cmp(x.m_ZP, y.m_ZP) == BN_CMP_EQ);
}

bool operator!=(const ZP &x, const ZP &y) {
  return (zmbignum_cmp(x.m_ZP, y.m_ZP) != BN_CMP_EQ);
}

ZP operator<<(const ZP &a, int b) {
  // left shift
  ZP zr = a;
  zmbignum_lshift(zr.m_ZP, zr.m_ZP, b);
  return zr;
}

ZP operator>>(const ZP &a, int b) {
  // right shift
  ZP zr = a;
  zmbignum_rshift(zr.m_ZP, zr.m_ZP, b);
  return zr;
}

void ZP::serialize(OpenABEByteString &result) const
{
  result.clear();
  result.insertFirstByte(OpenABE_ELEMENT_ZP);
  this->getLengthAndByteString(result);
}

void ZP::deserialize(OpenABEByteString &input)
{
  size_t inputSize = input.size(), hdrLen = 3;

  // first byte is the group type
  if (input.at(0) == OpenABE_ELEMENT_ZP && inputSize > hdrLen)
  {
    uint16_t len = 0;
    // read 2 bytes from right to left
    len |= input.at(2);        // Moves to 0x00FF
    len |= (input.at(1) << 8); // Moves to 0xFF00

    uint8_t *bstr = (input.getInternalPtr() + hdrLen);
    zmbignum_fromBin(this->m_ZP, bstr, len);
    if (isOrderSet && zmbignum_cmp(this->m_ZP, this->order) == BN_CMP_GT)
      zmbignum_mod(this->m_ZP, this->order);
  }
}

bool ZP::isEqual(ZObject *z) const
{
  ZP *z1 = dynamic_cast<ZP *>(z);
  return (z1 != NULL) && (*z1 == *this);
}

OpenABEByteString ZP::getByteString() const
{
  size_t length = zmbignum_countbytes(this->m_ZP);

  uint8_t data[length + 1];
  memset(data, 0, length);
  zmbignum_toBin(this->m_ZP, data, length);

  OpenABEByteString z;
  z.appendArray(data, length);
  return z;
}

string ZP::getBytesAsString()
{
  OpenABEByteString z;
  z = this->getByteString();
  return z.toHex();
}

void ZP::getLengthAndByteString(OpenABEByteString &z) const
{
  size_t length = zmbignum_countbytes(this->m_ZP);

  uint8_t data[length];
  memset(data, 0, length);
  zmbignum_toBin(this->m_ZP, data, length);

  z.pack16bits((uint16_t)length);
  z.appendArray(data, length);
}


#if 0
/********************************************************************************
 * Implementation of the GT class
 ********************************************************************************/

GT::GT(std::shared_ptr<BPGroup> bgroup)
{
    this->isInit = true;
    this->bgroup = bgroup;
    // does init and sets the point to infinity
    gt_set_to_infinity(GET_BP_GROUP(this->bgroup), &this->m_GT);
    shouldCompress_ = true;
}

GT::GT(const GT& w)
{
    if (w.bgroup != nullptr) {
        this->bgroup = w.bgroup;
    } else {
        throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
    }
    gt_init(GET_BP_GROUP(this->bgroup), &this->m_GT);
    gt_copy_const(this->m_GT, w.m_GT);
    this->isInit = true;
    this->shouldCompress_ = w.shouldCompress_;
}

GT&
GT::operator=(const GT& w)
{
    if (this->isInit) {
        if(w.bgroup != nullptr) {
            this->bgroup = w.bgroup;
        }
        if (is_elem_null(this->m_GT)) {
            if (this->bgroup)
                gt_init(GET_BP_GROUP(this->bgroup), &this->m_GT);
            else
                ro_error();
        }
        gt_copy_const(this->m_GT, w.m_GT);
        this->shouldCompress_ = w.shouldCompress_;
    }
    else ro_error();
    return *this;
}

GT::~GT()
{
    if (this->isInit) {
        gt_element_free(this->m_GT);
        this->isInit = false;
    }
}


GT operator*(const GT& x,const GT& y)
{
	GT z = x; // , y1 = y;
	gt_mul_op(GET_BP_GROUP(z.bgroup), z.m_GT, z.m_GT, const_cast<GT&>(y).m_GT);
	return z;
}

GT&
GT::operator*=(const GT& x)
{
	GT r(*this);
	*this = r * x;
	return *this;
}

GT operator/(const GT& x,const GT& y)
{
	GT z = x;
	// z = x * y^-1
	gt_div_op(GET_BP_GROUP(z.bgroup), z.m_GT, const_cast<GT&>(x).m_GT, const_cast<GT&>(y).m_GT);
	return z;
}

GT GT::exp(ZP z)
{
	GT gt(*this);
#if defined(BP_WITH_OPENSSL)
    GT_ELEM_exp(GET_BP_GROUP(gt.bgroup), gt.m_GT, gt.m_GT, z.m_ZP, NULL);
    //ASSERT(rc == 1, OpenABE_ERROR_INVALID_INPUT);
#else
    gt_exp(gt.m_GT, gt.m_GT, z.m_ZP);
#endif
	return gt;
}

GT operator-(const GT& g)
{
	GT gt(g);
#if defined(BP_WITH_OPENSSL)
	GT_ELEM_inv(GET_BP_GROUP(gt.bgroup), gt.m_GT, gt.m_GT, NULL);
#else
	gt_inv(gt.m_GT, gt.m_GT);
#endif
	return gt;
}

void GT::setIdentity()
{
#if defined(BP_WITH_OPENSSL)
    GT_ELEM_set_to_unity(GET_BP_GROUP(this->bgroup), this->m_GT);
    //ASSERT(rc == 1, oabe::OpenABE_ERROR_INVALID_INPUT);
#else
    gt_set_unity(this->m_GT);
#endif
}

bool GT::isInfinity()
{
    return gt_is_unity_check(GET_BP_GROUP(this->bgroup), this->m_GT);
}

bool GT::ismember(bignum_t order)
{
	bool result;
	gt_ptr r;
	gt_init(GET_BP_GROUP(this->bgroup), &r);
	gt_exp_op(GET_BP_GROUP(this->bgroup), r, this->m_GT, order);
	result = gt_is_unity_check(GET_BP_GROUP(this->bgroup), r);
	gt_element_free(r);
	return result;
}

ostream& operator<<(ostream& os, const GT& gt)
{
#if defined(BP_WITH_OPENSSL)
    OpenABEByteString s;
    gt_convert_to_bytestring(GET_BP_GROUP(gt.bgroup), s, gt.m_GT, NO_COMPRESS);
    os << "(" << s.toHex() << ")";
#else
	gt_write_ostream(os, const_cast<GT&>(gt).m_GT, DEC);
#endif
	return os;
}

bool operator==(const GT& x,const GT& y)
{
    bool result;
#if defined(BP_WITH_OPENSSL)
    result = (GT_ELEM_cmp(x.m_GT, y.m_GT) == G_CMP_EQ);
#else
    result = (gt_cmp(const_cast<GT&>(x).m_GT, const_cast<GT&>(y).m_GT) == G_CMP_EQ);
#endif
    return result;
}

bool operator!=(const GT& x, const GT& y)
{
    bool result;
#if defined(BP_WITH_OPENSSL)
    result = (GT_ELEM_cmp(x.m_GT, y.m_GT) != G_CMP_EQ);
#else
    result = (gt_cmp(const_cast<GT&>(x).m_GT, const_cast<GT&>(y).m_GT) != G_CMP_EQ);
#endif
    return result;
}


void
GT::serialize(OpenABEByteString &result) const
{
    OpenABEByteString tmp;
    int compress = shouldCompress_ ? COMPRESS : NO_COMPRESS;

    if(this->isInit) {
        gt_convert_to_bytestring(GET_BP_GROUP(this->bgroup), tmp, const_cast<GT&>(*this).m_GT, compress);
        // pack the resulting ciphertext in result
        result.clear();
        result.insertFirstByte(OpenABE_ELEMENT_GT);
        result.smartPack(tmp);
    }
}

void
GT::deserialize(OpenABEByteString &input)
{
    OpenABEByteString gt_bytes;
    size_t index = 0;

    if(this->isInit && this->bgroup != nullptr) {
        // first byte is the group type
        uint8_t element_type = input.at(index);
        if(element_type == OpenABE_ELEMENT_GT) {
            index++;
            gt_bytes = input.smartUnpack(&index);
            if (is_elem_null(this->m_GT)) {
                gt_init(GET_BP_GROUP(this->bgroup), &this->m_GT);
            }
            gt_convert_to_point(GET_BP_GROUP(this->bgroup), gt_bytes, this->m_GT);
            return;
        }
    }
    ASSERT(false, OpenABE_ERROR_ELEMENT_NOT_INITIALIZED);
}

bool
GT::isEqual(ZObject *z) const
{
	GT *z1 = dynamic_cast<GT*>(z);
	if(z1 != NULL) {
		return *z1 == *this;
	}
	return false;
}

#if !defined(BP_WITH_OPENSSL)
void fp12_write_ostream(ostream& os, fp12_t a, int radix) {
    os << "[(";
    fp6_write_ostream(os, a[0], radix);
    os << "),(";
    fp6_write_ostream(os, a[1], radix);
    os << "]";
}

void fp6_write_ostream(ostream &os, fp6_t a, int radix) {
    os << "{";
    fp2_write_ostream(os, a[0], radix);
    os << ",";
    fp2_write_ostream(os, a[1], radix);
    os << ",";
    fp2_write_ostream(os, a[2], radix);
    os << "}";
}

void fp2_write_ostream(ostream& os, fp2_t a, int radix) {
    os << "<";
    fp_write_ostream(os, a[0], radix);
    os << ",";
    fp_write_ostream(os, a[1], radix);
    os << ">";
}

void fp_write_ostream(ostream& os, fp_t a, int radix) {
    char strBuf[MAX_BYTES];
    fp_write_str(strBuf, MAX_BYTES, a, radix);
    os << strBuf;
}

void ep2_write_ostream(ostream &os, ep2_t p, int radix) {
    os << "[";
    fp2_write_ostream(os, p->x, radix);
    os << ",";
    fp2_write_ostream(os, p->y, radix);
//    os << ",";
//    fp2_write_ostream(os, p->z, radix);
    os << "]";
}

void ep_write_ostream(ostream &os, ep_t p, int radix) {
    // base field
    os << "[";
    fp_write_ostream(os, p->x, radix);
    os << ",";
    fp_write_ostream(os, p->y, radix);
    os << "]";
}
#endif

#endif