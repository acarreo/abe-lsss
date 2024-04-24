/**
 * @file hashattributes.cpp
 * @brief This file contains functions for hashing attributes and policies.
 */

#include "lsss/hashattributes.h"
#include "lsss/zpolicy.h"
#include "lsss/zattributelist.h"

#include <set>
#include <iostream>
#include <sstream>
#include <algorithm>


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


#if 0
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
 * Replaces all instances of a specified word within a string, provided they 
 * constitute whole words. The function respects specific delimiters such as 
 * parentheses and spaces, as well as the beginning or end of the string. 
 * This ensures that substrings forming part of a larger word are not replaced.
 *
 * @param str The string in which to replace the word.
 * @param oldWord The word to be replaced.
 * @param newWord The new word to replace the old word.
 */
void replaceWholeWord(std::string& str, const std::string& oldWord, const std::string& newWord) {
  size_t pos = 0;
  while ((pos = str.find(oldWord, pos)) != std::string::npos) {
    if ((pos == 0 || str[pos - 1] == '(' || str[pos - 1] == ' ') &&
        (pos + oldWord.length() == str.length()
        || str[pos + oldWord.length()] == ')'
        || str[pos + oldWord.length()] == ' '
        || str[pos + oldWord.length()] == '\0'))
    {
      str.replace(pos, oldWord.length(), newWord);
      pos += newWord.length();
    } else {
      pos++;
    }
  }
}

/**
 * @brief Extracts words from a string. This function is used to extract
 * set of unique attributes from a policy string. Don't use this function
 * complex policies.
 *
 * @param str The string from which to extract words.
 * @return std::set<std::string> The set of extracted unqique words.
 */
std::set<std::string> extractWords(const std::string& str) {
  std::set<std::string> words;
  std::istringstream iss(str);
  std::string word;

  while (iss >> word) {
    if (word != "or" && word != "and") {
      while (!word.empty() && (word.front() == '(' || word.front() == ')')) {
        word.erase(0, 1);
      }
      while (!word.empty() && (word.back() == '(' || word.back() == ')')) {
        word.pop_back();
      }

      words.insert(word);
    }
  }
  
  return words;
}
#endif

/**
 * Replaces all instances of a specified word within a string with a new word.
 *
 * @param str The string in which to replace the word.
 * @param oldWord The word to be replaced.
 * @param newWord The new word to replace the old word.
 */
void replaceAll(std::string& str, const std::string& oldWord, const std::string& newWord) {
  size_t pos = 0;
  while ((pos = str.find(oldWord, pos)) != std::string::npos) {
    str.replace(pos, oldWord.length(), newWord);
    pos += newWord.length();
  }
}

/**
 * @brief Hashes an attribute using the Blake2s algorithm.
 *
 * @param attribute The attribute to be hashed.
 * @return std::string The hashed attribute.
 */
std::string hashAttribute(const std::string& attribute) {
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
  std::string final_policy = policy;

  auto attributes = createPolicyTree(policy)->getAttrCompleteSet();

  for (const auto& attr : attributes) {
    replaceAll(final_policy, attr, hashAttribute(attr));
  }

  return final_policy;
}

/**
 * @brief Hashes a list of attributes by hashing each attribute individually.
 * 
 * @param attributes The list of attributes to be hashed.
 * @return std::string The hashed attributes separated by '|'.
 */
std::string hashAttributesList(const std::string& attributes) {
  std::string hashed_attr = attributes;

  auto attrList = createAttributeList(attributes);
  auto attrSet = attrList->getAttributeList();

  for (const auto& att : *attrSet) {
    replaceAll(hashed_attr, att, hashAttribute(att));
  }

  return hashed_attr;
}
