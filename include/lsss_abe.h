#ifndef __LSSS_ABE_H__
#define __LSSS_ABE_H__

#include "abe/zabe.h"
#include "abe/zcontainer.h"
#include "abe/zinteger.h"
#include "abe/zkdf.h"
#include "abe/zkey.h"
#include "abe/zkeystore.h"
#include "abe/zpairing.h"
#include "abe/zsymcrypto.h"
#include "abe/zsymkey.h"

// Define shorter aliases for some classes for easier usage in code
using ByteString = OpenABEByteString;      // Alias for OpenABEByteString class
using CryptoKDF = OpenABEKDF;              // Alias for OpenABEKDF class
using CryptoSymKey = OpenABESymKey;        // Alias for OpenABESymKey class
using CryptoKeyStore = OpenABEKeystore;    // Alias for OpenABEKeystore class
using CryptoContainer = OpenABEContainer;  // Alias for OpenABEContainer class

#endif // __LSSS_ABE_H__
