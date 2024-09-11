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

// #include <lsss_abe/lsss_abe.h>
#include <lsss_abe.h>

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
    ASSERT_TRUE(authEncStream->decryptUpdate(ctBlock1, plaintext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->decryptUpdate(ctBlock2, plaintext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->decryptFinalize(plaintext) == OpenABE_NOERROR);

    ASSERT_TRUE(plaintext == (ptBlock1 + ptBlock2));
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
