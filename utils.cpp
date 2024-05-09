#include <memory>
#include <lsss_abe.h>
#include "utils.h"


using namespace std;

/*****************************************************************************
 * Utility functions for Schema ID
 *****************************************************************************/

OpenABE_SCHEME OpenABE_getSchemeID(uint8_t id) {
  OpenABE_SCHEME schemeID;
  switch (id) {
  case OpenABE_SCHEME_NONE:
  case OpenABE_SCHEME_PKSIG_ECDSA:
  case OpenABE_SCHEME_AES_GCM:
  case OpenABE_SCHEME_PK_OPDH:
  case OpenABE_SCHEME_CP_WATERS:
  case OpenABE_SCHEME_KP_GPSW:
  case OpenABE_SCHEME_CP_WATERS_CCA:
  case OpenABE_SCHEME_KP_GPSW_CCA:
    schemeID = (OpenABE_SCHEME)id;
    break;
  default:
    throw OpenABE_ERROR_INVALID_SCHEME_ID;
  }
  return schemeID;
}

const string OpenABE_convertSchemeIDToString(OpenABE_SCHEME id) {
  string scheme = "";
  switch (id) {
  case OpenABE_SCHEME_NONE:
    scheme = "No Scheme";
    break;
  case OpenABE_SCHEME_PKSIG_ECDSA:
    scheme = OpenABE_EC_DSA;
    break;
  case OpenABE_SCHEME_PK_OPDH:
    scheme = OpenABE_PK_ENC;
    break;
  case OpenABE_SCHEME_CP_WATERS_CCA:
  case OpenABE_SCHEME_CP_WATERS:
    scheme = OpenABE_CP_ABE;
    break;
  case OpenABE_SCHEME_KP_GPSW_CCA:
  case OpenABE_SCHEME_KP_GPSW:
    scheme = OpenABE_KP_ABE;
    break;
  default:
    throw OpenABE_ERROR_INVALID_SCHEME_ID;
  }
  return scheme;
}

OpenABE_SCHEME OpenABE_convertStringToSchemeID(const string id) {
  if (id == OpenABE_EC_DSA) {
    return OpenABE_SCHEME_PKSIG_ECDSA;
  } else if (id == OpenABE_PK_ENC) {
    return OpenABE_SCHEME_PK_OPDH;
  } else if (id == OpenABE_CP_ABE) {
    return OpenABE_SCHEME_CP_WATERS;
  } else if (id == OpenABE_KP_ABE) {
    return OpenABE_SCHEME_KP_GPSW;
  } else {
    return OpenABE_SCHEME_NONE;
  }
}


/********************************************************************************
 * OpenABEKeystoreManager utility methods for ciphertexts and keys
 ********************************************************************************/

unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABECiphertext &ciphertext) {
  OpenABE_SCHEME scheme_type = ciphertext.getSchemeType();
  OpenABEByteString *policy_str = NULL;
  OpenABEAttributeList *attrList = NULL;

  // check the scheme type
  switch (scheme_type) {
  case OpenABE_SCHEME_CP_WATERS:
  case OpenABE_SCHEME_CP_WATERS_CCA:
    policy_str = ciphertext.getByteString("policy");
    ASSERT_NOTNULL(policy_str);
    return unique_ptr<OpenABEFunctionInput>(createPolicyTree(policy_str->toString()));
    break;
  case OpenABE_SCHEME_KP_GPSW:
  case OpenABE_SCHEME_KP_GPSW_CCA:
    attrList = (OpenABEAttributeList *)ciphertext.getComponent("attributes");
    ASSERT_NOTNULL(attrList);
    return unique_ptr<OpenABEFunctionInput>(createAttributeList(attrList->toCompactString()));
    break;
  default:
    break;
  }
  return nullptr;
}

OpenABEFunctionInputType getFunctionInputType(OpenABEKey *key) {
  OpenABE_SCHEME scheme_type = OpenABE_getSchemeID(key->getAlgorithmID());
  // check the scheme type
  switch(scheme_type) {
    case OpenABE_SCHEME_CP_WATERS:
    case OpenABE_SCHEME_CP_WATERS_CCA:
      return FUNC_ATTRLIST_INPUT;
      break;
    case OpenABE_SCHEME_KP_GPSW:
    case OpenABE_SCHEME_KP_GPSW_CCA:
      return FUNC_POLICY_INPUT;
      break;
    default:
      break;
  }
  return FUNC_INVALID_INPUT;
}

/*
 * NOTE: caller is responsible for deleting memory associated with OpenABEFunctionInput
 */
unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABEKey *key) {
  OpenABE_SCHEME scheme_type = OpenABE_getSchemeID(key->getAlgorithmID());
  OpenABEByteString *policy_str = NULL;
  OpenABEAttributeList *attrList = NULL;
  unique_ptr<OpenABEPolicy> policy = nullptr;

  // check the scheme type
  switch(scheme_type) {
    case OpenABE_SCHEME_CP_WATERS:
    case OpenABE_SCHEME_CP_WATERS_CCA:
      // attributes are on the key for CP-ABE
      attrList = (OpenABEAttributeList*)key->getComponent("input");
      ASSERT_NOTNULL(attrList);
      return createAttributeList(attrList->toCompactString());
      break;
    case OpenABE_SCHEME_KP_GPSW:
    case OpenABE_SCHEME_KP_GPSW_CCA:
      // policy on the key for KP-ABE
      policy_str = key->getByteString("input");
      ASSERT_NOTNULL(policy_str);
      return createPolicyTree(policy_str->toString());
      break;
    default:
      break;
  }

  return nullptr;
}
