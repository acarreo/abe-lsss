/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 


#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <gtest/gtest.h>

// #include <abe_lsss/abe_lsss.h>
#include <abe_lsss.h>

using namespace std;

#define TEST_MSG_LEN        32
#define TEST_MSGBLOCK_LEN   16

#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)
#define TESTSUITE_DESCRIPTION(desc) ::testing::Test::RecordProperty("description", desc)


TEST(SK, TestStreamAuthEncForSKScheme) {
    TEST_DESCRIPTION("Testing Stream SK scheme enc/dec using randomly generated keys");
    shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
    OpenABEByteString plaintext, ciphertext, iv, tag;
    OpenABEByteString ptBlock1, ptBlock2, ctBlock1, ctBlock2;
    OpenABEByteString decrypted, decryptedBlock1, decryptedBlock2;

    // generate a random secret key of a certain size
    symkey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);

    unique_ptr<OpenABESymKeyAuthEncStream> authEncStream(new OpenABESymKeyAuthEncStream(DEFAULT_AES_SEC_LEVEL, symkey));

    getRandomBytes(ptBlock1, TEST_MSGBLOCK_LEN);
    getRandomBytes(ptBlock2, TEST_MSGBLOCK_LEN);

    ASSERT_TRUE(authEncStream->encryptInit(iv) == OpenABE_NOERROR);
    // set 0s for the AAD
    authEncStream->initAddAuthData(NULL, 0);
    ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);

    // perform update 1
    ASSERT_TRUE(authEncStream->encryptUpdate(ptBlock1, ciphertext) == OpenABE_NOERROR);

    // perform update 2
    ASSERT_TRUE(authEncStream->encryptUpdate(ptBlock2, ciphertext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->encryptFinalize(ciphertext, tag) == OpenABE_NOERROR);

    // split ciphertext into blocks
    ctBlock1 = ciphertext.getSubset(0, ptBlock1.size());
    ctBlock2 = ciphertext.getSubset(ptBlock1.size(), ptBlock2.size());

    // now try to decrypt the ciphertexts
    ASSERT_TRUE(authEncStream->decryptInit(iv, tag) == OpenABE_NOERROR);

    // set 0s for the AAD
    authEncStream->initAddAuthData(NULL, 0);
    ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);

    // perform decrypt updates in order (note: order of blocks must be managed by the user)
    ASSERT_TRUE(authEncStream->decryptUpdate(ctBlock1, decryptedBlock1) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->decryptUpdate(ctBlock2, decryptedBlock2) == OpenABE_NOERROR);

    decrypted = decryptedBlock1 + decryptedBlock2;
    ASSERT_TRUE(authEncStream->decryptFinalize(decrypted) == OpenABE_NOERROR);
    ASSERT_TRUE(decrypted == (ptBlock1 + ptBlock2));

    // FAILURE TEST: now try to decrypt the ciphertexts (out of order)
    plaintext.clear();
    ASSERT_TRUE(authEncStream->decryptInit(iv, tag) == OpenABE_NOERROR);

    // set 0s for the AAD
    authEncStream->initAddAuthData(NULL, 0);
    ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);
    // perform decrypt updates in order (note: order of blocks must be managed by the user)
    ASSERT_TRUE(authEncStream->decryptUpdate(ctBlock2, plaintext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->decryptUpdate(ctBlock1, plaintext) == OpenABE_NOERROR);
    ASSERT_FALSE(authEncStream->decryptFinalize(plaintext) == OpenABE_NOERROR);
}

TEST(SK, TestSymKeyHandlerForGCMMode) {
    TEST_DESCRIPTION("Testing Symmetric Key Handler with GCM mode using randomly generated keys");

    unique_ptr<OpenABESymKey> symKey = make_unique<OpenABESymKey>();
    symKey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
    string keyStr = symKey->getKeyBytes().toString();

    string plaintext, decrypted, ciphertext;
    OpenABEByteString randomPlaintext, aad;

    getRandomBytes(randomPlaintext, TEST_MSG_LEN);
    plaintext = randomPlaintext.toString();

    unique_ptr<SymKeyEncHandler> SKEHandler = make_unique<SymKeyEncHandler>(keyStr);

    SKEHandler->setAuthData(aad);
    ciphertext = SKEHandler->encrypt(plaintext);
    decrypted = SKEHandler->decrypt(ciphertext);

    ASSERT_TRUE(plaintext == decrypted);
}


// Test encryption and decryption from SymKeyEncHandler class
TEST(SKETest, TestSKEWithOpenABESymKey) {
  OpenABEByteString key_bytes, aad;
  OpenABEByteString plaintext, ciphertext, decrypted;
  std::string keyID = "testKeyID";

  getRandomBytes(plaintext, 128);
  getRandomBytes(aad, MIN_BYTE_LEN);

  std::shared_ptr<OpenABESymKey> key = std::make_unique<OpenABESymKey>(keyID);
  std::shared_ptr<OpenABESymKey> key_loaded = std::make_unique<OpenABESymKey>();

  ASSERT_TRUE(key->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES));
  ASSERT_TRUE(key->exportKeyToBytes(key_bytes) == OpenABE_NOERROR);
  ASSERT_TRUE(key_loaded->loadKeyFromBytes(key_bytes) == OpenABE_NOERROR);

  ASSERT_EQ(*key, *key_loaded);

  std::unique_ptr<SymKeyEncHandler> encHandler = std::make_unique<SymKeyEncHandler>(key);
  ASSERT_NO_THROW(ASSERT_NOTNULL(encHandler));
  encHandler->setAuthData(aad);

  ASSERT_TRUE(encHandler->encrypt(ciphertext, plaintext) == OpenABE_NOERROR);

  OpenABE_ERROR ret = OpenABE_ERROR_UNKNOWN;
  std::unique_ptr<SymKeyEncHandler> decHandler = std::make_unique<SymKeyEncHandler>(key_loaded);
  ASSERT_NO_THROW(ASSERT_NOTNULL(decHandler));
  ASSERT_NO_THROW(ret = decHandler->decrypt(decrypted, ciphertext));
  ASSERT_TRUE(ret == OpenABE_NOERROR);
  ASSERT_EQ(plaintext, decrypted);
}

TEST(SKETest, TestSKEWrongKeyAndWrongAAD) {
  OpenABEByteString key, aad;
  OpenABEByteString plaintext, ciphertext;
  std::string keyID = "testKeyID";

  getRandomBytes(plaintext, 128);

  getRandomBytes(aad, MIN_BYTE_LEN);
  getRandomBytes(key, DEFAULT_SYM_KEY_BYTES);

  // Encryption -- generate ciphertext
  {
    std::unique_ptr<SymKeyEncHandler> encHandler = std::make_unique<SymKeyEncHandler>(key.toString());
    ASSERT_NO_THROW(ASSERT_NOTNULL(encHandler));
    ASSERT_TRUE(encHandler->encrypt(ciphertext, plaintext) == OpenABE_NOERROR);
  }

  // Test decryption with correct key
  {
    OpenABEByteString decrypted;
    OpenABE_ERROR ret = OpenABE_ERROR_UNKNOWN;

    std::unique_ptr<SymKeyEncHandler> encHandler = std::make_unique<SymKeyEncHandler>(key.toString());
    ASSERT_NO_THROW( ret = encHandler->decrypt(decrypted, ciphertext) );
    ASSERT_TRUE(ret == OpenABE_NOERROR);
    ASSERT_EQ(plaintext, decrypted);
  }

  // Test with wrong key
  {
    OpenABEByteString decrypted, wrong_key;
    OpenABE_ERROR ret = OpenABE_ERROR_UNKNOWN;

    getRandomBytes(wrong_key, DEFAULT_SYM_KEY_BYTES);

    std::unique_ptr<SymKeyEncHandler> encHandler = std::make_unique<SymKeyEncHandler>(wrong_key.toString());
    ASSERT_NO_THROW(ASSERT_NOTNULL(encHandler));
    ASSERT_ANY_THROW( ret = encHandler->decrypt(decrypted, ciphertext));
    ASSERT_NE(ret, OpenABE_NOERROR);
    ASSERT_TRUE(decrypted.size() == 0);
    ASSERT_NE(plaintext, decrypted);
  }

  // Test with wrong AAD
  {
    OpenABEByteString decrypted, wrong_aad;
    OpenABE_ERROR ret = OpenABE_ERROR_UNKNOWN;

    getRandomBytes(wrong_aad, MIN_BYTE_LEN);

    std::unique_ptr<SymKeyEncHandler> encHandler = std::make_unique<SymKeyEncHandler>(key.toString());
    ASSERT_NO_THROW(ASSERT_NOTNULL(encHandler));
    encHandler->setAuthData(wrong_aad);

    ASSERT_ANY_THROW( ret = encHandler->decrypt(decrypted, ciphertext) );
    ASSERT_NE(ret, OpenABE_NOERROR);
    ASSERT_EQ(decrypted.size(), 0);
    ASSERT_NE(plaintext, decrypted);
  }
}


// Test encryption and decryption from SymKeyEncHandler class
TEST(SKETest, TestSKEWithSymKey) {
  OpenABEByteString sym_key;
  OpenABEByteString plaintext, ciphertext, decrypted;

  getRandomBytes(plaintext, 128);
  getRandomBytes(sym_key, DEFAULT_SYM_KEY_BYTES);

  std::unique_ptr<SymKeyEncHandler> encHandler = std::make_unique<SymKeyEncHandler>(sym_key.toString());
  ASSERT_TRUE(encHandler->encrypt(ciphertext, plaintext) == OpenABE_NOERROR);
  ASSERT_TRUE(encHandler->decrypt(decrypted, ciphertext) == OpenABE_NOERROR);
  ASSERT_EQ(plaintext, decrypted);
}


TEST(hashToSymmetricKey, TestKDF2) {
    TEST_DESCRIPTION("Testing hashToSymmetricKey using KDF2");
    size_t len = 16;
    size_t keyLen = 0;
    OpenABEByteString key;

    GT gt;
    gt.setRandom();

    uint8_t* keyData = gt.hashToBytes(&keyLen);
    key.fillBuffer(0, keyLen);
    if (memcpy(key.getInternalPtr(), keyData, keyLen) == NULL) {
        cout << "memcpy failed" << endl;
    }

    OpenABEKDF kdf;
    OpenABEByteString DK = kdf.ComputeKDF2(key, len);

    OpenABESymKey symkey;
    symkey.hashToSymmetricKey(gt, len);
    OpenABEByteString DK0 = symkey.getKeyBytes();

    ASSERT_TRUE(DK == DK0);
}

TEST(SymKey, SKGeneration) {
    TEST_DESCRIPTION("Testing Symmetric Key Generation");
    OpenABESymKey symkey;

    ASSERT_TRUE(symkey.generateSymmetricKey(DEFAULT_SYM_KEY_BYTES));
    ASSERT_TRUE(symkey.generateSymmetricKey(SYM_KEY_BYTES));
    ASSERT_THROW(symkey.generateSymmetricKey(17), OpenABE_ERROR);

    OpenABESymKey symkey1("toto_key");
    OpenABESymKey symkey2;
    OpenABEByteString exportedKey;

    ASSERT_TRUE(symkey1.generateSymmetricKey(DEFAULT_SYM_KEY_BYTES));
    ASSERT_TRUE(symkey1.exportKeyToBytes(exportedKey) == OpenABE_NOERROR);
    ASSERT_TRUE(symkey2.loadKeyFromBytes(exportedKey) == OpenABE_NOERROR);

    ASSERT_TRUE(symkey1 == symkey2);

    // cout << "Exported Key:" << endl << exportedKey.toHex() << endl;
    // cout << "Key bytes without header:" << endl << symkey1.getKeyBytes().toHex() << endl;
}


int main(int argc, char **argv) {
  int rc;

  InitializeOpenABE();

  ::testing::InitGoogleTest(&argc, argv);
  rc = RUN_ALL_TESTS();

  ShutdownOpenABE();

  return rc;
}
