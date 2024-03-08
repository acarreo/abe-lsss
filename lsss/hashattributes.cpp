/**
 * @file hashattributes.cpp
 * @brief This file contains functions for hashing attributes and policies.
 */

#include "hashattributes.h"


// std::vector<std::string> splitByWord(const std::string& stringToSplit, const std::string& delim);
std::vector<std::string> split(const std::string &s, char delim);


/* helper methods to assist with serializing and base-64 encoding group elements */
static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789-_";

/* Note that the following was borrowed from Copyright (C) 2004-2008 Ren� Nyffenegger (*/

bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '-') || (c == '_'));
}

std::string Base64Encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

std::string Base64Decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  size_t in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  // The only case where we have a valid input and the following
  // if happens is terminating '=' characters
  if (in_ < encoded_string.size()) {
    // Look for terminating '='s, maximum 2
    if (encoded_string.size() - in_ > 2) {
      return std::string();
      //throw //OpenABE_ERROR_INVALID_INPUT;
    }

    size_t tmp = in_;
    for (; tmp < encoded_string.size(); tmp++) {
        if (encoded_string[tmp] != '=') {
          break;
        }
    }
    if (tmp != encoded_string.size()) {
      return std::string();
      //throw //OpenABE_ERROR_INVALID_INPUT;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}


/**
 * @brief Splits a string by a delimiter and returns a vector of substrings.
 *
 * @param stringToSplit The string to be split.
 * @param delim The delimiter to split the string by.
 * @return std::vector<std::string> The vector of substrings.
 */
std::vector<std::string> splitByWord(const std::string& stringToSplit, const std::string& delim) {
  std::vector<std::string> result;
  std::string str = stringToSplit;
  size_t del_len = delim.length();
  size_t pos = 0;

  while (pos < str.length()) {
    pos = str.find(delim);
    result.push_back(str.substr(0, pos));
    str.erase(0, pos + del_len);
  }

  return result;
}

/**
 * @brief Hashes an attribute using the Blake2s algorithm.
 *
 * @param attribute The attribute to be hashed.
 * @return std::string The hashed attribute.
 */
std::string hashAttribute(const std::string& attribute) {
  if (attribute.find("Date") != std::string::npos ||
      attribute.find("Floor") != std::string::npos)
    return attribute;

  uint8_t digest[SIZEOF_ATTRIBUTE];
  blake2s(digest, SIZEOF_ATTRIBUTE, (uint8_t*)attribute.c_str(), attribute.size(), NULL, 0);

  return "A:" + Base64Encode(digest, SIZEOF_ATTRIBUTE);
}

/**
 * @brief Hashes a policy by hashing each attribute in the policy.
 *
 * @param policy The policy to be hashed.
 * @return std::string The hashed policy.
 */
std::string hashPolicy(const std::string policy) {
  std::string final_policy = "";

  std::vector<std::string> vect_split_or = splitByWord(policy, " or ");
  for (std::string elm : vect_split_or) {

    std::vector<std::string> vect_split_and = splitByWord(elm, " and ");
    for (std::string y : vect_split_and) {

      size_t pos = y.rfind('('); // reverse find '('
      if (pos != std::string::npos) {
        final_policy += y.substr(0, pos + 1) + hashAttribute(y.substr(pos + 1, y.length() - pos));
        final_policy += " and ";
      }

      pos = y.find(')'); // find ')'
      if (pos != std::string::npos) {
        final_policy += hashAttribute(y.substr(0, pos)) + y.substr(pos, y.length());
        final_policy += " and ";
      }
    }
    // remove last " and "
    final_policy = final_policy.substr(0, final_policy.length() - 5);
    final_policy += " or ";
  }
  // remove last " or "
  final_policy = final_policy.substr(0, final_policy.length() - 4);

  return final_policy;
}

/**
 * @brief Hashes a list of attributes by hashing each attribute individually.
 * 
 * @param attributes The list of attributes to be hashed.
 * @return std::string The hashed attributes separated by '|'.
 */
std::string hashattributesList(const std::string& attributes) {
  std::vector<std::string> attr_list = split(attributes, '|');
  std::string hashed_attr = "";

  for (const auto& att : attr_list) {
    hashed_attr += hashAttribute(att) + "|";
  }
  // remove last "|"
  hashed_attr = hashed_attr.substr(0, hashed_attr.length() - 1);

  return hashed_attr;
}
