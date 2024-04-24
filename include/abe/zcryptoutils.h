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
///	\file   zcryptoutils.h
///
///	\brief  Miscellaneous cryptographic utilities.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZCRYPTOUTILS_H__
#define __ZCRYPTOUTILS_H__

#include "zabe.h"

// forward declare GT (for now)
class GT;
// hashing GT elements into a bytestring
bool  OpenABEUtilsHashToString(GT &input, uint32_t keyLen, OpenABEByteString &result);
std::string OpenABEHashKey(const std::string attr_key);

#endif	// __ZCRYPTOUTILS_H__
