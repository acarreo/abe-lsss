#include "../schemes/zcontextcpwaters.h"

/*!
 * Create a new OpenABEContextABE for a specific scheme type.
 *
 * @param[in]   the scheme type
 * @return      A pointer to the OpenABE context structure
 */
std::unique_ptr<OpenABEContextABE> createContextABE(OpenABE_SCHEME scheme_type) {
  switch (scheme_type) {
    case OpenABE_SCHEME_CP_WATERS:
      return std::make_unique<OpenABEContextCPWaters>();
    case OpenABE_SCHEME_KP_GPSW:
      std::cout << "------------------<<<< Not implemented yet >>>>------------------" << std::endl;
      return nullptr;
    default:
      std::cout << "-----------------<<<< Scheme not supported >>>>------------------" << std::endl;
      return nullptr;
  }
}

/*!
 * Create a new OpenABEContextScheme for a specific scheme type (for CPA security).
 *
 * @param[in]   the scheme type
 * @return      A pointer to the OpenABE context structure
 */
std::unique_ptr<OpenABEContextSchemeCPA> createContextABESchemeCPA(OpenABE_SCHEME scheme_type) {
  std::unique_ptr<OpenABEContextABE> kemContext(createContextABE(scheme_type));

  if (!kemContext) {
    // createContextABE failed, return nullptr
    return nullptr;
  }

  return std::unique_ptr<OpenABEContextSchemeCPA>(new OpenABEContextSchemeCPA(std::move(kemContext)));
}
