#ifndef __ALL_HPP__
#define __ALL_HPP__

#include <cstdint>
#include <string>

extern "C" {
#include <relic/relic.h>
}

#include "../lsss/zlsss.h"

#include "zerror.h"
#include "zexception.h"


/// @typedef    OpenABE_STATE
///
/// @brief      Enumeration of global states for the Zeutro toolkit library

typedef enum _OpenABE_STATE {
  OpenABE_STATE_UNINITIALIZED = 0,
  OpenABE_STATE_ERROR = 1,
  OpenABE_STATE_READY = 2
} OpenABE_STATE;

/// @typedef    OpenABE_SCHEME
///
/// @brief      Enumeration of supported FE schemes

typedef enum _OpenABE_SCHEME {
  OpenABE_SCHEME_NONE = 0,
  OpenABE_SCHEME_PKSIG_ECDSA = 60,
  OpenABE_SCHEME_AES_CBC = 70,
  OpenABE_SCHEME_AES_GCM = 71,
  OpneABE_SCHEME_AES_GCM_STREAM = 72,
  OpenABE_SCHEME_PK_OPDH = 100,
  OpenABE_SCHEME_CP_WATERS = 101,
  OpenABE_SCHEME_KP_GPSW = 102,
  OpenABE_SCHEME_CP_WATERS_CCA = 201,
  OpenABE_SCHEME_KP_GPSW_CCA = 202
} OpenABE_SCHEME;

//
// hash function prefix definitions
#define CCA_HASH_FUNCTION_ONE 0x1A
#define CCA_HASH_FUNCTION_TWO 0x1F
#define SCHEME_HASH_FUNCTION 0x2A
#define KDF_HASH_FUNCTION_PREFIX 0x2B

#define OpenABE_MAX_KDF_BITLENGTH 0xFFFFFFFF


#define SAFE_MALLOC(size) malloc(size)
#define SAFE_FREE(val) free(val)
#define SAFE_DELETE(ref)                                                       \
  if (ref != NULL) {                                                           \
    delete ref;                                                                \
    ref = NULL;                                                                \
  }

#define OpenABE_LOG_ERROR(str) (std::cerr << "ERROR: " << str << std::endl)

#ifdef DEBUG
 #define DEBUG_ELEMENT_PRINTF(...) element_printf(__VA_ARGS__)
 #define OpenABE_LOG_AND_THROW(str, err)                                            \
  OpenABE_LOG_ERROR((str));                                                        \
  throw(err);
#define OpenABE_LOG(str)                                                           \
  OpenABE_LOG_ERROR((str));

#else
 #define DEBUG_ELEMENT_PRINTF(...)
 #define OpenABE_LOG_AND_THROW(str, err)                                            \
  throw(err);
 #define OpenABE_LOG(str) /* do nothing */
#endif

//
// Core library header files
//

#if defined(OS_REDHAT_LINUX)
   #include <cstddef>
   #include <cstdio>
   using ::max_align_t;
#endif
#include <gmpxx.h>


#if defined(BP_WITH_OPENSSL)
const std::string DEFAULT_MATH_LIB = "OpenSSL";
#else /* WITH RELIC */
const std::string DEFAULT_MATH_LIB = "RELIC";
#endif

///
/// scheme identifiers
///

#define OpenABE_EC_DSA "EC-DSA"
#define OpenABE_PK_ENC "PK-ENC"
#define OpenABE_CP_ABE "CP-ABE"
#define OpenABE_KP_ABE "KP-ABE"
#define OpenABE_MA_ABE "MA-ABE"


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

#endif // __ALL_HPP__
