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
#include "../../utils/common.h"


/// @typedef    OpenABE_STATE
///
/// @brief      Enumeration of global states for the Zeutro toolkit library

typedef enum _OpenABE_STATE {
  OpenABE_STATE_UNINITIALIZED = 0,
  OpenABE_STATE_ERROR = 1,
  OpenABE_STATE_READY = 2
} OpenABE_STATE;

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

#endif // __ALL_HPP__
