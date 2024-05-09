#ifndef __UTILS_H__
#define __UTILS_H__

#include "lsss/zfunctioninput.h"

class OpenABEFunctionInput;
class OpenABECiphertext;

std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABECiphertext& ciphertext);
std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABEKey *key);
OpenABEFunctionInputType getFunctionInputType(OpenABEKey *key);



#endif // endif __UTILS_H__
