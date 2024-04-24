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
/// \file   zfunctioninput.cpp
///
/// \brief  Base class for arbitrary function inputs.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABEFUNCTIONINPUT_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include "lsss/zfunctioninput.h"

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEFunctionInput class
 ********************************************************************************/
//namespace oabe {

/*!
 * Constructor for the OpenABEFunctionInput class.
 *
 */

OpenABEFunctionInput::OpenABEFunctionInput() : ZObject(), m_Type(FUNC_INVALID_INPUT) {}

/*!
 * Destructor for the OpenABEFunctionInput class.
 *
 */

OpenABEFunctionInput::~OpenABEFunctionInput() {}

// }