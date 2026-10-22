/**
 * @file abe.h
 * @brief Namespaced ABE context and input API.
 */

#ifndef ABE_LSSS_ABE_H
#define ABE_LSSS_ABE_H

#include "abe_lsss/api.h"
#include "abe/zabe.h"
#include "abe/zsymkey.h"
#include "abe/zcontextabe.h"
#include "lsss/zbytestring.h"
#include "lsss/zfunctioninput.h"

#include <memory>
#include <string>

namespace abe_lsss {

using Scheme = ::OpenABE_SCHEME;
using ByteString = ::OpenABEByteString;
using Ciphertext = ::OpenABECiphertext;
using FunctionInput = ::OpenABEFunctionInput;
using CpaContext = ::OpenABEContextSchemeCPA;

inline constexpr Scheme cp_waters = OpenABE_SCHEME_CP_WATERS;
inline constexpr Scheme kp_gpsw = OpenABE_SCHEME_KP_GPSW;

/**
 * @brief Create one of the supported CPA-secure ABE contexts.
 *
 * Returns an empty pointer when the scheme is not implemented.
 */
std::unique_ptr<CpaContext> create_context(Scheme scheme);

/**
 * @brief Parse a monotone ABE policy.
 *
 * Returns an empty pointer when parsing fails.
 */
std::unique_ptr<FunctionInput> parse_policy(const std::string& policy);

/**
 * @brief Parse a pipe-separated attribute list.
 *
 * Returns an empty pointer when parsing fails.
 */
std::unique_ptr<FunctionInput> parse_attributes(const std::string& attributes);

}

#endif
