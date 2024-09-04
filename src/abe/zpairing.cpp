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
/// \file   zpairing.cpp
///
/// \brief  Implementation for bilinear maps (or pairings).
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __ZPAIRING_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <string>

#include "abe/zpairing.h"
#include <lsss_abe.h>

using namespace std;


// Utility functions

/*!
 * Global pairing library initialization
 *
 * @return OpenABE_NOERROR or an error code
 */

OpenABE_ERROR
zMathInitLibrary()
{
  if (core_init() == RLC_OK && pc_param_set_any() == RLC_OK)
    return OpenABE_NOERROR;
  
  return OpenABE_ERROR_LIBRARY_NOT_INITIALIZED;
}

/*!
 * Global pairing library shutdown
 *
 * @return OpenABE_NOERROR or an error code
 */

OpenABE_ERROR
zMathShutdownLibrary()
{
  core_clean();
  return OpenABE_NOERROR;
}


/********************************************************************************
 * Implementation of the OpenABEPairing class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEPairing class.
 *
 */

OpenABEPairing::OpenABEPairing() : ZObject()
{    
  AssertLibInit();
  this->bpgroup  = make_shared<BPGroup>();
  zmbignum_init(&this->order);
  this->bpgroup->getGroupOrder(this->order);
}

/*!
 * Constructor for the OpenABEPairing class.
 *
 */
OpenABEPairing::OpenABEPairing(const OpenABEPairing &copyFrom) : ZObject()
{
  AssertLibInit();
  this->bpgroup  = make_shared<BPGroup>();
  zmbignum_init(&this->order);
  this->bpgroup->getGroupOrder(this->order);
}

/*!
 * Destructor for the OpenABEPairing class.
 *
 */
OpenABEPairing::~OpenABEPairing()
{
  zmbignum_free(this->order);
  this->bpgroup.reset();
}

void
OpenABEPairing::initZP(ZP& result, uint32_t v)
{
  result = ZP(v);
  result.setOrder(this->order);
}

ZP OpenABEPairing::initZP()
{
  ZP z;
  z.setOrder(this->order);
  return z;
}

/*!
 * Generate and return a random group element in ZP.
 *
 * @return group element in ZP
 */
ZP
OpenABEPairing::randomZP()
{
  ZP result;
  result.setRandom(this->order);
  return result;
}

/*!
 * Generate and return a random group element in G1.
 *
 * @return group element in G1
 */
G1
OpenABEPairing::randomG1()
{
	G1 result;
	result.setRandom();
	return result;
}

/*!
 * Generate and return a random group element in G2.
 *
 * @return group element in G2
 */
G2
OpenABEPairing::randomG2()
{
	G2 result;
	result.setRandom();
	return result;
}

G1
OpenABEPairing::hashToG1(OpenABEByteString& keyPrefix, string msg)
{
  OpenABEByteString tmp;
  // set the key prefix
  tmp = keyPrefix;
  // append the message
  tmp += msg;

  uint8_t digest[RLC_MD_LEN];
  _hash_to_bytes_(digest, tmp.getInternalPtr(), tmp.size());

  G1 g1;
  g1_map(g1.m_G1, digest, RLC_MD_LEN);
  return g1;
}

GT
OpenABEPairing::pairing(const G1& g1, const G2& g2)
{
  GT result;
  pc_map(result.m_GT, g1.m_G1, g2.m_G2);
  return result;
}

void
OpenABEPairing::multi_pairing(GT& gt, std::vector<G1>& g1, std::vector<G2>& g2) {
  if (g1.size() != g2.size() || g1.size() == 0) {
    throw OpenABE_ERROR_INVALID_LENGTH;
  }

  const size_t n = g1.size();
  g1_t g_1[n];
  g2_t g_2[n];
  for (size_t i = 0; i < n; i++) {
    g1_init(g_1[i]);
    g1_copy(g_1[i], g1.at(i).m_G1);
    g2_init(g_2[i]);
    g2_copy(g_2[i], g2.at(i).m_G2);
  }
  pc_map_sim(gt.m_GT, g_1, g_2, n);
  for (size_t i = 0; i < n; i++) {
    g1_free(g_1[i]);
    g2_free(g_2[i]);
  }
}


OpenABEByteString
OpenABEPairing::hashToBytes(uint8_t *buf, uint32_t buf_len)
{
  uint8_t hash[RLC_MD_LEN];
  _hash_to_bytes_(hash, buf, buf_len);

  OpenABEByteString b;
  b.appendArray(hash, RLC_MD_LEN);
  return b;
}

// implements a variable-sized hash function
// block_len = len / md_len ... rounding up
// H(00 || hash_byte || m) || H(01 || hash_byte || m) || ... || H(n || hash_byte || m)
// ... where 'n' is block_len and 'm' is message
OpenABEByteString
OpenABEPairing::hashFromBytes(OpenABEByteString &buf, uint32_t target_len, uint8_t hash_prefix)
{
  // compute number of hash blocks needed
  int block_len = ceil(((double)target_len) / (uint32_t)RLC_MD_LEN);
  // set the hash_len
  int hash_len = block_len * RLC_MD_LEN;
  uint8_t hash[hash_len+1];
  memset(hash, 0, hash_len+1);

  OpenABEByteString buf2 = buf;
  uint8_t count = 0;

  buf2.insertFirstByte(hash_prefix);
  buf2.insertFirstByte(count);
  uint8_t *ptr = buf2.getInternalPtr();
  uint8_t *hash_ptr = hash;

  for(int i = 0; i < block_len; i++) {
    // H(count || hash_prefix || buf)
    _hash_to_bytes_(hash_ptr, buf2.getInternalPtr(), buf2.size());
    count++;
    ptr[0] = count;      // change block number
    hash_ptr += RLC_MD_LEN; // move ptr by RLC_MD_LEN size
  }

  OpenABEByteString b;
  b.appendArray(hash, target_len);
  return b;
}

