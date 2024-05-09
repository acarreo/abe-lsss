#ifndef __COMMON_H__
#define __COMMON_H__

#include <memory>

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


///
/// scheme identifiers
///
#define OpenABE_EC_DSA "EC-DSA"
#define OpenABE_PK_ENC "PK-ENC"
#define OpenABE_CP_ABE "CP-ABE"
#define OpenABE_KP_ABE "KP-ABE"
#define OpenABE_MA_ABE "MA-ABE"

#endif /* ifndef __COMMON_H__ */
