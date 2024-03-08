
#ifndef __HASHATTRIBUTES_H__
#define __HASHATTRIBUTES_H__

#include <vector>
#include <string>
#include <blake2.h>

#define SIZEOF_ATTRIBUTE 9


std::string Base64Encode(unsigned char const* bytes_to_encode, unsigned int in_len);
std::string Base64Decode(std::string const& encoded_string);

std::string hashAttribute(const std::string& attribute);
std::string hashPolicy(const std::string policy);
std::string hashattributesList(const std::string& attributes);

#endif // __HASHATTRIBUTES_H__
