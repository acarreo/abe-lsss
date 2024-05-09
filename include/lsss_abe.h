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
#include "abe/zcontextabe.h"
#include "abe/zcontextcca.h"
#include "abe/zcontextske.h"
#include "abe/zcontextpke.h"
#include "abe/zcontextcpwaters.h"
#include "abe/zcontextpksig.h"
#include "abe/zkeymgr.h"

///
/// Utility functions
///

void InitializeOpenABE();
void ShutdownOpenABE();
void AssertLibInit();

const char *OpenABE_errorToString(OpenABE_ERROR err);
const uint32_t OpenABE_getLibraryVersion();

// curve to/from string conversion functions
OpenABE_SCHEME OpenABE_getSchemeID(uint8_t id);
// convert strings to/from OpenABE_SCHEME
const std::string OpenABE_convertSchemeIDToString(OpenABE_SCHEME schemeID);
OpenABE_SCHEME OpenABE_convertStringToSchemeID(const std::string id);

// creates KEM context for PKE & ABE schemes
OpenABEContextPKE *OpenABE_createContextPKE(OpenABE_SCHEME scheme_type);
OpenABEContextABE *OpenABE_createContextABE(OpenABE_SCHEME scheme_type);

// PKE scheme context API
std::unique_ptr<OpenABEContextSchemePKE>
OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME scheme_type);
std::unique_ptr<OpenABEContextCCA>
OpenABE_createABEContextForKEM(OpenABE_SCHEME scheme_type);

// CPA scheme context API
std::unique_ptr<OpenABEContextSchemeCPA>
OpenABE_createContextABESchemeCPA(OpenABE_SCHEME scheme_type);

// CCA scheme context API
std::unique_ptr<OpenABEContextSchemeCCA>
OpenABE_createContextABESchemeCCA(OpenABE_SCHEME scheme_type);

// CCA scheme context API with amortization support
std::unique_ptr<OpenABEContextSchemeCCAWithATZN>
OpenABE_createContextABESchemeCCAWithATZN(OpenABE_SCHEME scheme_type);

// PKSIG scheme context API
// std::unique_ptr<OpenABEContextSchemePKSIG> OpenABE_createContextPKSIGScheme();

// curve to/from string conversion functions
OpenABE_SCHEME OpenABE_getSchemeID(uint8_t id);
// convert strings to/from OpenABE_SCHEME

// void OpenABE_setGroupObject(std::shared_ptr<ZGroup> &group, uint8_t id);

///
/// OpenABE initialization per thread
///
class OpenABEStateContext {
public:
  /*! \brief Initialize OpenABE per thread
   *
   * The following function needs to be called exactly once at the
   * beginning of any OpenABE-using thread except for the thread that
   * calls OpenABE_initialize.  This must be done in a thread before any
   * OpenABE functionality is invoked in that thread, otherwise, your
   * program may crash arbitrarily.
   */
  void initializeThread();

  /*! \brief Shutdown OpenABE per thread
   *
   * The following function needs to be called exactly once at the
   * end of any OpenABE-using thread except for the thread that calls
   * OpenABE_shutdown.  This should be done before the destruction of
   * the thread. If you forget to call this function, it is invoked
   * in the destructor of the OpenABE state context.
   */
  void shutdownThread();

  OpenABEStateContext() : isInitialized_(false) {
    // initializeThread() on constructor initialization
    initializeThread();
    isInitialized_ = true;
  }

  ~OpenABEStateContext() {
    // in case user forgets to call shutdownThread()
    if (isInitialized_) {
      shutdownThread();
    }
  }

private:
  bool isInitialized_;
};

void getRandomBytes(uint8_t *buf, size_t buf_len);
void getRandomBytes(OpenABEByteString &buf, size_t buf_len);

inline void _hash_to_bytes_(uint8_t* digest, uint8_t *buf, uint32_t buf_len) {
  md_map(digest, buf, buf_len);
}


// Define shorter aliases for some classes for easier usage in code
using ByteString = OpenABEByteString;      // Alias for OpenABEByteString class
using CryptoKDF = OpenABEKDF;              // Alias for OpenABEKDF class
using CryptoSymKey = OpenABESymKey;        // Alias for OpenABESymKey class
using CryptoKeyStore = OpenABEKeystore;    // Alias for OpenABEKeystore class
using CryptoContainer = OpenABEContainer;  // Alias for OpenABEContainer class

#endif // __LSSS_ABE_H__
