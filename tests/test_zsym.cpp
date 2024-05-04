/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>

#include <lsss_abe/lsss_abe.h>

using namespace std;

std::string toHex(const std::string& str) {
  std::stringstream hex;
  for (size_t i = 0; i < str.size(); ++i) {
    hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(str[i]));
  }
  return hex.str();
}

int main(int argc, char **argv) {

  InitializeOpenABE();

  string the_key, derived_key, key_data, ciphertext, plaintext1, plaintext2;
  string the_key_str, derived_key_str;

  cout << "Generate random key..." << endl;
  generateSymmetricKey(the_key, 32);
  the_key_str = toHex(the_key);
  cout << the_key_str << endl;

  std::unique_ptr<OpenABESymKeyHandle> keyHandle(new OpenABESymKeyHandle(the_key));

  cout << "Export key..." << endl;
  keyHandle->exportKey(derived_key);

  derived_key_str = toHex(derived_key);
  cout << "Derived Key: " << derived_key_str << endl;

  // assert that key and derived key are not equal
  if (the_key_str.compare(derived_key_str) != 0) {
    cout << "Exported a different key!" << endl;
  }

  // test encryption
  plaintext1 = "this is plaintext!";
  keyHandle->encrypt(ciphertext, plaintext1);

  cout << "Ciphertext -- ctx_size: " << ciphertext.size() << ", plain_len: " << plaintext1.size() << endl;
  cout << toHex(ciphertext) << endl;

  // test decryption
  keyHandle->decrypt(plaintext2, ciphertext);

  if (plaintext1 != plaintext2) {
      cout << "Decryption failed!!" << endl;
      return 1;
  }
  cout << "Successful Decryption!" << endl;

  ShutdownOpenABE();

  return 0;
}
