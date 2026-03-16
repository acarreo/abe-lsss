#ifndef __UTILS_H__
#define __UTILS_H__

#include "lsss/zfunctioninput.h"

std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABECiphertext& ciphertext);
std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABEKey *key);
OpenABEFunctionInputType getFunctionInputType(OpenABEKey *key);

OpenABEContextABE *createContextABE(OpenABE_SCHEME scheme_type);

// CPA scheme context API
std::unique_ptr<OpenABEContextSchemeCPA> createContextABESchemeCPA(OpenABE_SCHEME scheme_type);

#endif // endif __UTILS_H__
