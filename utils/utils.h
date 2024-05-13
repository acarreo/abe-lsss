#ifndef __UTILS_H__
#define __UTILS_H__

#include "lsss/zfunctioninput.h"

// Define shorter aliases for some classes for easier usage in code
using ByteString = OpenABEByteString;      // Alias for OpenABEByteString class
using CryptoKDF = OpenABEKDF;              // Alias for OpenABEKDF class
using CryptoSymKey = OpenABESymKey;        // Alias for OpenABESymKey class
using CryptoKeystore = OpenABEKeystore;    // Alias for OpenABEKeystore class
using CryptoContainer = OpenABEContainer;  // Alias for OpenABEContainer class


std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABECiphertext& ciphertext);
std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABEKey *key);
OpenABEFunctionInputType getFunctionInputType(OpenABEKey *key);

OpenABEContextABE *createContextABE(OpenABE_SCHEME scheme_type);

// CPA scheme context API
std::unique_ptr<OpenABEContextSchemeCPA>
createContextABESchemeCPA(OpenABE_SCHEME scheme_type);


#endif // endif __UTILS_H__
