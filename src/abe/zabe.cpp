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
/// \file   openabe.cpp
///
/// \brief  Main implementation for the Zeutro Toolkit (OpenABE).
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OPENABE_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

#include <lsss_abe.h>

using namespace std;


/********************************************************************************
 * Library global variables
 ********************************************************************************/

// flag for the library initialization state
OpenABE_STATE gLibraryState = OpenABE_STATE_UNINITIALIZED;


/********************************************************************************
 * Core API
 ********************************************************************************/

/*!
 * Global initialization for the toolkit. This routine must be called before 
 * any others.
 *
 * @return				OpenABE_ERROR_NONE or an error code.
 */

static OpenABE_ERROR
OpenABE_initialize() {
  OpenABE_ERROR result = OpenABE_ERROR_LIBRARY_NOT_INITIALIZED;

  // If the library is in a pre-initialized state, we can initialize it and go.
  // Otherwise return an error.
  if (gLibraryState == OpenABE_STATE_UNINITIALIZED) {

    // Initialize the pairing library
    result = zMathInitLibrary();
  
    // Set the error file to stderr.
    // gErrorLog = new zErrorLog();

    // Future library pre-processing, self-checks, etc. go here.

    // Set the library state to READY
    // initializedOpenssl = init_openssl;
    gLibraryState = OpenABE_STATE_READY;
    result = OpenABE_NOERROR;
  }

  return result;
}

/*!
 * Internal routine for global shutdown for the library.
 *
 * @return				OpenABE_ERROR_NONE or an error code.
 */

static OpenABE_ERROR
OpenABE_shutdown() {
  OpenABE_ERROR result = OpenABE_NOERROR;

  // Shut down the pairing library
  result = zMathShutdownLibrary();

  gLibraryState = OpenABE_STATE_UNINITIALIZED;

  return result;
}

void AssertLibInit() {
  if (gLibraryState == OpenABE_STATE_UNINITIALIZED) {
    throw runtime_error(OpenABE_errorToString(OpenABE_ERROR_LIBRARY_NOT_INITIALIZED));
  }
}

/*!
 * Global initialization for the toolkit (for RELIC and OpenSSL library).
 * This routin should be called prior to any other OpenABE API calls.
 *
 */

void InitializeOpenABE() {
  // initialize RELIC
  OpenABE_ERROR rc = OpenABE_initialize();
  if (rc != OpenABE_NOERROR) {
    throw runtime_error("InitializeOpenABE: Could not initialize the OpenABE");
  }
}

/*!
 * Global shutdown for the library.  This routine should be called prior to application
 * exit.
 */

void ShutdownOpenABE() {
  OpenABE_ERROR rc = OpenABE_shutdown();
  if (rc != OpenABE_NOERROR) {
    throw runtime_error("ShutdownOpenABE: Could not shutdown the OpenABE");
  }
}

void OpenABEStateContext::initializeThread() {
  if (!isInitialized_) {
    // Initialize the pairing library
    zMathInitLibrary();
  }
}

void OpenABEStateContext::shutdownThread() {
  if (isInitialized_) {
    // check whether we have called init already
    zMathInitLibrary();
    // reset the initialization state
    isInitialized_ = false;
  }
}

// unique_ptr<OpenABEContextCCA> OpenABE_createABEContextForKEM(OpenABE_SCHEME scheme_type) {
//   unique_ptr<OpenABEContextCCA> kemContextCCA;
//   // create a scheme context for a given scheme type
//   unique_ptr<OpenABEContextSchemeCPA> schemeContext =
//       OpenABE_createContextABESchemeCPA(scheme_type);
//   if (!schemeContext) {
//     throw OpenABE_ERROR_INVALID_SCHEME_ID;
//   }
//   // create a CCA context (KEM version) based on the scheme context
//   kemContextCCA.reset(new OpenABEContextGenericCCA(std::move(schemeContext)));

//   return kemContextCCA;
// }

/*!
 * Create a new OpenABEContextSchemeCCA for a specific scheme type (for CCA security).
 *
 * @param[in]   the scheme type
 * @return      A pointer to the OpenABE context structure
 */

// unique_ptr<OpenABEContextSchemeCCA>
// OpenABE_createContextABESchemeCCA(OpenABE_SCHEME scheme_type) {
//   unique_ptr<OpenABEContextCCA> kemContextCCA =
//       OpenABE_createABEContextForKEM(scheme_type);
//   // wrap the CCA KEM context in a CCA scheme context for use by user
//   return unique_ptr<OpenABEContextSchemeCCA>(
//       new OpenABEContextSchemeCCA(std::move(kemContextCCA)));
// }

/*!
 * Create a new OpenABEContextSchemeCCAWithATZN for a specific scheme type (for CCA security).
 *
 * @param[in]   the scheme type
 * @return      A pointer to the OpenABE context structure
 */

// unique_ptr<OpenABEContextSchemeCCAWithATZN>
// OpenABE_createContextABESchemeCCAWithATZN(OpenABE_SCHEME scheme_type) {
//   unique_ptr<OpenABEContextCCA> kemContextCCA =
//       OpenABE_createABEContextForKEM(scheme_type);
//   // wrap the CCA KEM context in a CCA scheme context with amortization
//   return unique_ptr<OpenABEContextSchemeCCAWithATZN>(
//       new OpenABEContextSchemeCCAWithATZN(std::move(kemContextCCA)));
// }


/*!
 * Create a new OpenABEContextPKE for a specific scheme type.
 *
 * @param[in]   a RNG object
 * @param[in]   the scheme type
 * @return      A pointer to the OpenABE context structure
 */

// OpenABEContextPKE *OpenABE_createContextPKE(OpenABE_SCHEME scheme_type) {
//   OpenABEContextPKE *newContext = NULL;

//   /* Depending on the scheme, set up the context using the appropriate
//    * constructor.
//    * This will set appropriate function pointers within the context so the other
//    * calls won't require a switch statement. */
//     switch(scheme_type) {
//     case OpenABE_SCHEME_PK_OPDH:
//       newContext = (OpenABEContextPKE *)new OpenABEContextOPDH();
//       break;
//     default:
//       // gErrorLog.log("Could not instantiate unknown scheme type", __LINE__,
//       // __FILE__);
//       newContext = NULL;
//     }

//     return newContext;
// }

/*!
 * Create a new OpenABEContextSchemePKE for a specific scheme type (includes CCA security).
 *
 * @param[in]   the scheme type
 * @return      A pointer to the OpenABE context structure
 */

// unique_ptr<OpenABEContextSchemePKE>
// OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME scheme_type) {
//   // consruct an RNG object
//   // create a KEM context for PKE given the RNG object
//   unique_ptr<OpenABEContextPKE> pkeKEMContext(OpenABE_createContextPKE(scheme_type));
//   if (!pkeKEMContext) {
//     throw OpenABE_ERROR_INVALID_SCHEME_ID;
//   }
//   // return a scheme context for PKE given the KEM context
//   return unique_ptr<OpenABEContextSchemePKE>(
//       new OpenABEContextSchemePKE(move(pkeKEMContext)));
// }


// unique_ptr<OpenABEContextSchemePKSIG> OpenABE_createContextPKSIGScheme() {
//   // first create a PKSIG context (wrapper around OpenSSL)
//   unique_ptr<OpenABEContextPKSIG> pksig(new OpenABEContextPKSIG);
//   // return a unique ptr to a PKSIG scheme context (smoothen out API)
//   // with an underlying PKSIG context
//   return unique_ptr<OpenABEContextSchemePKSIG>(
//       new OpenABEContextSchemePKSIG(move(pksig)));
// }

/*!
 * Return the OpenABE version.
 *
 * @return    The library version as a unsigned integer.
 */

const uint32_t OpenABE_getLibraryVersion() {
  return OpenABE_LIBRARY_VERSION;
}
