#include "zcontextcpwaters.h"
#include "zcontextkpgpsw.h"
#include "abe_lsss/abe.h"
#include "../utils/utils.h"

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
      return std::make_unique<OpenABEContextKPGPSW>();
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

std::unique_ptr<abe_lsss::CpaContext> abe_lsss::create_context(Scheme scheme) {
  return createContextABESchemeCPA(scheme);
}

std::unique_ptr<abe_lsss::FunctionInput> abe_lsss::parse_policy(const std::string& policy) {
  return createPolicyTree(policy);
}

std::unique_ptr<abe_lsss::FunctionInput> abe_lsss::parse_attributes(
    const std::string& attributes) {
  return createAttributeList(attributes);
}
