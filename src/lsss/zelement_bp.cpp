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

#include "lsss/zbytestring.h"
#include "lsss/zobject.h"
#include "lsss/zelement_bp.h"

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

void ZP::setRandom(ZP &order) {
  if (!order.isOrderSet) {
    if (!this->isOrderSet) {
      this->isOrderSet = true;
      zmbignum_copy(this->order, order.m_ZP);
    }
    zmbignum_rand(this->m_ZP, order.m_ZP);
  }
}

void ZP::setPrime(uint16_t n_bits) {
  if (this->isInit && !this->isOrderSet) {
    bn_gen_prime_basic(this->m_ZP, n_bits);
  }
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

/********************************************************************************
 * Implementation of the G1 class
 ********************************************************************************/

G1::G1() {
  g1_init(this->m_G1);
  g1_set_infty(this->m_G1);
  isInit = true;
}

G1::G1(const G1 &w) {
  g1_init(this->m_G1);
  g1_copy(this->m_G1, w.m_G1);
  isInit = true;
}

G1::G1(const g1_t &w) {
  g1_init(this->m_G1);
  g1_copy(this->m_G1, w);
  isInit = true;
}

G1::G1(uint8_t *buffer, int bufferSize) {
  if (bufferSize != G1_SIZE) {
    cerr << "Error : Invalid buffer size for G1 element." << endl;
    exit(-1);
  }
  g1_init(this->m_G1);
  g1_read_bin(this->m_G1, buffer, bufferSize);
  isInit = true;
}

G1::~G1() {
  if (isInit) {
    g1_free(this->m_G1);
    isInit = false;
  }
}

G1& G1::operator*=(const ZP k) {
  G1 tmp(*this);
  *this = tmp * k;
  return *this;
}

G1& G1::operator+=(const G1 &x) {
  G1 tmp(*this);
  *this = tmp + x;
  return *this;
}

G1& G1::operator=(const G1 &w) {
  if (this != &w) {
    g1_copy(this->m_G1, w.m_G1);
  }
  return *this;
}

void G1::setRandom() {
  if (isInit) g1_rand(this->m_G1);
}

void G1::setGenerator() {
  if (isInit) g1_get_gen(this->m_G1);
}

int G1::getSize() const {
  return g1_size_bin(this->m_G1, _COMPRESSION_);
}

size_t G1::getSizeInBytes() const {
  //Add 3 bytes : 1 byte for the group type and 2 bytes for the length
  return this->getSize() + sizeof(uint8_t) + sizeof(uint16_t);
}

bool G1::ismember() const {
  return isInit && g1_is_valid(this->m_G1);
}

uint8_t* G1::hashToBytes(size_t *size) const {
  int len = this->getSize();
  uint8_t buffer[len];
  g1_write_bin(buffer, len, this->m_G1, _COMPRESSION_);

  std::unique_ptr<uint8_t[]> hash(new uint8_t[RLC_MD_LEN]);
  md_map(hash.get(), buffer, len);
  *size = RLC_MD_LEN;

  return hash.release();
}

G1 G1::operator*(const ZP k) const {
  G1 tmp;
  g1_mul(tmp.m_G1, this->m_G1, k.m_ZP);
  return tmp;
}

G1 G1::operator-(const G1 &x) const {
  G1 tmp;
  g1_neg(tmp.m_G1, x.m_G1);
  return tmp;
}

G1 G1::operator+(const G1 &x) const {
  G1 tmp;
  g1_add(tmp.m_G1, this->m_G1, x.m_G1);
  return tmp;
}

bool G1::operator==(const G1 &x) const {
  return (g1_cmp(m_G1, x.m_G1) == RLC_EQ);
}

bool G1::isEqual(ZObject *z) const {
  G1 *z1 = dynamic_cast<G1 *>(z);
  return (z1 != NULL) && (*z1 == *this);
}

G1* G1::clone() const {
  return new G1(*this);
}

uint8_t* G1::getBytes(int *bufferSize) const {
  int size = this->getSize();
  uint8_t *buffer = (uint8_t *)malloc(size);
  g1_write_bin(buffer, size, this->m_G1, _COMPRESSION_);
  *bufferSize = size;
  return buffer;
}

void G1::serialize(OpenABEByteString &result) const {
  OpenABEByteString tmp;
  int len = 0;

  if (this->isInit) {
    uint8_t *bytes = this->getBytes(&len);
    tmp.appendArray(bytes, len);

    result.clear();
    result.insertFirstByte(OpenABE_ELEMENT_G1);
    result.smartPack(tmp);
  }
}

void G1::deserialize(OpenABEByteString &input) {
  OpenABEByteString g1_bytes;
  size_t index = 0;

  if (this->isInit && (input.at(index++) == OpenABE_ELEMENT_G1)) {
    g1_bytes = input.smartUnpack(&index);
    G1 tmp(g1_bytes.data(), g1_bytes.size());
    *this = tmp;
  }
}


/********************************************************************************
 * Implementation of the G2 class
 ********************************************************************************/

G2::G2() {
  g2_init(this->m_G2);
  g2_set_infty(this->m_G2);
  isInit = true;
}

G2::G2(const G2 &w) {
  g2_init(this->m_G2);
  g2_copy(this->m_G2, w.m_G2);
  isInit = true;
}

G2::G2(const g2_t &w) {
  g2_init(this->m_G2);
  g2_copy(this->m_G2, w);
  isInit = true;
}

G2::G2(uint8_t *buffer, int bufferSize) {
  if (bufferSize != G2_SIZE) {
    cerr << "Error : Invalid buffer size for G2 element." << endl;
    exit(-1);
  }
  g2_init(this->m_G2);
  g2_read_bin(this->m_G2, buffer, bufferSize);
  isInit = true;
}

G2::~G2() {
  if (isInit) {
    g2_free(this->m_G2);
    isInit = false;
  }
}

G2& G2::operator*=(const ZP k) {
  G2 tmp(*this);
  *this = tmp * k;
  return *this;
}

G2& G2::operator+=(const G2 &x) {
  G2 tmp(*this);
  *this = tmp + x;
  return *this;
}

G2& G2::operator=(const G2 &w) {
  if (this != &w) {
    g2_copy(this->m_G2, w.m_G2);
  }
  return *this;
}

void G2::setRandom() {
  if (isInit) g2_rand(this->m_G2);
}

void G2::setGenerator() {
  if (isInit) g2_get_gen(this->m_G2);
}

uint8_t* G2::hashToBytes(size_t *size) const {
  int len = this->getSize();
  uint8_t buffer[len];
  g2_write_bin(buffer, len, this->m_G2, _COMPRESSION_);

  std::unique_ptr<uint8_t[]> hash(new uint8_t[RLC_MD_LEN]);
  md_map(hash.get(), buffer, len);
  *size = RLC_MD_LEN;

  return hash.release();
}

int G2::getSize() const {
  return g2_size_bin(this->m_G2, _COMPRESSION_);
}

size_t G2::getSizeInBytes() const {
  //Add 3 bytes : 1 byte for the group type and 2 bytes for the length
  return this->getSize() + sizeof(uint8_t) + sizeof(uint16_t);
}

bool G2::ismember() const {
  return isInit && g2_is_valid(this->m_G2);
}

G2 G2::operator*(const ZP k) const {
  G2 tmp;
  g2_mul(tmp.m_G2, this->m_G2, k.m_ZP);
  return tmp;
}

G2 G2::operator-(const G2 &x) const {
  G2 tmp;
  g2_neg(tmp.m_G2, x.m_G2);
  return tmp;
}

G2 G2::operator+(const G2 &x) const {
  G2 tmp;
  g2_add(tmp.m_G2, this->m_G2, x.m_G2);
  return tmp;
}

bool G2::operator==(const G2 &x) const {
  return (g2_cmp(this->m_G2, x.m_G2) == RLC_EQ);
}

bool G2::isEqual(ZObject *z) const {
  G2 *z1 = dynamic_cast<G2 *>(z);
  return (z1 != NULL) && (*z1 == *this);
}

G2* G2::clone() const {
  return new G2(*this);
}

uint8_t* G2::getBytes(int *bufferSize) const {
  int size = this->getSize();
  uint8_t *buffer = (uint8_t *)malloc(size);
  g2_write_bin(buffer, size, this->m_G2, _COMPRESSION_);
  *bufferSize = size;
  return buffer;
}

void G2::serialize(OpenABEByteString &result) const {
  OpenABEByteString tmp;
  int len = 0;

  if (this->isInit) {
    uint8_t *bytes = this->getBytes(&len);
    tmp.appendArray(bytes, len);

    result.clear();
    result.insertFirstByte(OpenABE_ELEMENT_G2);
    result.smartPack(tmp);
  }
}

void G2::deserialize(OpenABEByteString &input) {
  OpenABEByteString g2_bytes;
  size_t index = 0;

  if (this->isInit && (input.at(index++) == OpenABE_ELEMENT_G2)) {
    g2_bytes = input.smartUnpack(&index);
    G2 tmp(g2_bytes.data(), g2_bytes.size());
    *this = tmp;
  }
}


/********************************************************************************
 * Implementation of the GT class
 ********************************************************************************/

GT::GT() {
  gt_init(this->m_GT);
  gt_set_unity(this->m_GT);
  isInit = true;
}

GT::GT(const GT &w) {
  gt_init(this->m_GT);
  gt_copy(this->m_GT, w.m_GT);
  isInit = true;
}

GT::~GT() {
  if (isInit) {
    gt_free(this->m_GT);
    isInit = false;
  }
}

void GT::setIdentity() {
  if (isInit) gt_set_unity(this->m_GT);
}

void GT::setRandom() {
  if (isInit) gt_rand(this->m_GT);
}

void GT::setGenerator() {
  if (isInit) gt_get_gen(this->m_GT);
}

uint8_t* GT::hashToBytes(size_t *size) const {
  OpenABEByteString buffer;
  this->serialize(buffer);
  std::unique_ptr<uint8_t[]> hash(new uint8_t[RLC_MD_LEN]);
  md_map(hash.get(), buffer.data(), buffer.size());
  *size = RLC_MD_LEN;

  return hash.release();
}

int GT::getSize() const {
  return gt_size_bin((static_cast<GT>(*this)).m_GT, _COMPRESSION_);
}

size_t GT::getSizeInBytes() const {
  //Add 3 bytes : 1 byte for the group type and 2 bytes for the length
  return this->getSize() + sizeof(uint8_t) + sizeof(uint16_t);
}

bool GT::isIdentity() const {
  return isInit && gt_is_unity(this->m_GT);
}

bool GT::ismember() const {
  return isInit && gt_is_valid(this->m_GT);
}

GT GT::exp(const ZP k) const {
  GT tmp;
  gt_exp(tmp.m_GT, this->m_GT, k.m_ZP);
  return tmp;
}

GT GT::inverse() const {
  GT tmp;
  gt_inv(tmp.m_GT, this->m_GT);
  return tmp;
}

GT GT::operator*(const GT &x) const {
  GT tmp;
  gt_mul(tmp.m_GT, this->m_GT, x.m_GT);
  return tmp;
}

GT GT::operator/(const GT &x) const {
  GT tmp;
  gt_inv(tmp.m_GT, x.m_GT);
  gt_mul(tmp.m_GT, this->m_GT, tmp.m_GT);
  return tmp;
}

GT& GT::operator*=(const GT &x) {
  GT tmp(*this);
  *this = tmp * x;
  return *this;
}

GT& GT::operator=(const GT &x) {
  gt_copy(this->m_GT, x.m_GT);
  return *this;
}

bool GT::operator==(const GT& x) const {
  return (gt_cmp(this->m_GT, x.m_GT) == RLC_EQ);
}

bool GT::isEqual(ZObject* z) const {
  GT *z1 = dynamic_cast<GT *>(z);
  return (z1 != NULL) && (*z1 == *this);
}

GT* GT::clone() const {
  return new GT(*this);
}

uint8_t* GT::getBytes(int *bufferSize) const {
  int size = this->getSize();
  uint8_t *buffer = (uint8_t *)malloc(size);
  gt_write_bin(buffer, size, this->m_GT, _COMPRESSION_);
  *bufferSize = size;
  return buffer;
}

void GT::serialize(OpenABEByteString &result) const {
  OpenABEByteString tmp;
  int len = 0;

  if(this->isInit) {
    uint8_t *bytes = this->getBytes(&len);
    tmp.appendArray(bytes, len);

    result.clear();
    result.insertFirstByte(OpenABE_ELEMENT_GT);
    result.smartPack(tmp);
  }
}

void GT::deserialize(OpenABEByteString &input) {
  OpenABEByteString gt_bytes;
  size_t index = 0;

  if(this->isInit && (input.at(index++) == OpenABE_ELEMENT_GT)) {
    gt_bytes = input.smartUnpack(&index);
    gt_read_bin(this->m_GT, gt_bytes.data(), gt_bytes.size());
  }
}


GT pairing(const G1 &x, const G2 &y) {
  GT tmp;
  pc_map(tmp.m_GT, x.m_G1, y.m_G2);
  return tmp;
}
