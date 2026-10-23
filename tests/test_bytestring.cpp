#include <gtest/gtest.h>
#include <abe_lsss.h>


void __printVectUint8__(std::vector<uint8_t> &vec) {
  OpenABEByteString bytes;
  bytes.appendArray(vec.data(), vec.size());
  std::cout << bytes.toHex() << std::endl;
}

void __printByteString__(OpenABEByteString bytes) {
  std::cout << bytes.toHex() << std::endl;
}

TEST(OpenABEByteStringTest, ConvertionVector) {
  OpenABEByteString bytes, bytes2;
  getRandomBytes(bytes, 16);


  std::vector<uint8_t> vec = bytes;
  ASSERT_EQ(bytes, vec);

  std::cout << "--------------------------------------------------" << std::endl;
  __printVectUint8__(vec);
  std::cout << "--------------------------------------------------" << std::endl;
  __printVectUint8__(bytes);

  bytes2.appendArray(vec.data(), vec.size());
  ASSERT_EQ(bytes, bytes2);
}

TEST(OpenABEByteStringTest, EmptyStringHasNullSafeInternalPtr) {
  OpenABEByteString empty, packed;
  EXPECT_NO_THROW(empty.getInternalPtr());
  packed.smartPack(empty);
  EXPECT_EQ(packed.size(), 0u);
}

TEST(OpenABEByteStringTest, SmartPackRoundTripsAtSizeBoundaries) {
  for (size_t len : {1u, 255u, 256u, 65535u, 65536u}) {
    OpenABEByteString payload, packed;
    getRandomBytes(payload, len);
    packed.smartPack(payload);

    size_t index = 0;
    OpenABEByteString out = packed.smartUnpack(&index);
    EXPECT_EQ(out, payload) << "len=" << len;
    EXPECT_EQ(index, packed.size()) << "len=" << len;
  }
}

TEST(OpenABEByteStringTest, SmartUnpackRejectsTruncatedInput) {
  for (size_t len : {10u, 300u, 70000u}) {
    OpenABEByteString payload, packed;
    getRandomBytes(payload, len);
    packed.smartPack(payload);

    for (size_t cut = 0; cut < packed.size(); cut += (len > 1000 ? 997 : 1)) {
      OpenABEByteString truncated = packed.getSubset(0, cut);
      size_t index = 0;
      EXPECT_THROW(truncated.smartUnpack(&index), std::out_of_range)
          << "len=" << len << " cut=" << cut;
    }
  }
}

TEST(OpenABEByteStringTest, UnpackRejectsOversizedLengthFields) {
  // 32-bit length claims 4 GiB but only 3 bytes follow.
  OpenABEByteString lying;
  lying.push_back(0xFF); lying.push_back(0xFF);
  lying.push_back(0xFF); lying.push_back(0xFF);
  lying.push_back(1); lying.push_back(2); lying.push_back(3);
  size_t index = 0;
  EXPECT_THROW(lying.unpack(&index), std::out_of_range);

  OpenABEByteString lying16;
  lying16.push_back(0xFF); lying16.push_back(0xFF); lying16.push_back(7);
  index = 0;
  EXPECT_THROW(lying16.unpack16bits(&index), std::out_of_range);
}

TEST(OpenABEByteStringTest, SmartUnpackUnknownTypeYieldsEmpty) {
  OpenABEByteString bogus;
  bogus.push_back(0x00);
  size_t index = 0;
  EXPECT_EQ(bogus.smartUnpack(&index).size(), 0u);
  EXPECT_EQ(index, 1u);
}

TEST(OpenABEByteStringTest, SymKeyDecryptNeverAcceptsTamperedCiphertext) {
  OpenABESymKey key;
  ASSERT_TRUE(key.generateSymmetricKey(DEFAULT_SYM_KEY_BYTES));
  auto keyPtr = std::make_shared<OpenABESymKey>(key);
  SymKeyEncHandler handler(keyPtr);

  OpenABEByteString plaintext, ciphertext;
  getRandomBytes(plaintext, 64);
  ASSERT_EQ(handler.encrypt(ciphertext, plaintext), OpenABE_NOERROR);

  auto accepted_wrongly = [&](const OpenABEByteString &candidate) {
    OpenABEByteString out;
    try {
      if (handler.decrypt(out, candidate) != OpenABE_NOERROR) return false;
    } catch (const std::exception &) {
      return false;
    }
    return out != plaintext;
  };

  for (size_t cut = 0; cut < ciphertext.size(); cut++) {
    EXPECT_FALSE(accepted_wrongly(ciphertext.getSubset(0, cut))) << "cut=" << cut;
  }
  for (size_t i = 0; i < ciphertext.size(); i++) {
    OpenABEByteString flipped = ciphertext;
    flipped[i] ^= 0x01;
    EXPECT_FALSE(accepted_wrongly(flipped)) << "flip=" << i;
  }
}







int main(int argc, char **argv) {
  int rc;

  abe_lsss::initialize();

  relic_print_params();
  std::cout << "--------------------------------------------------" << std::endl;
  std::cout << "Compression for serialization: "
            << abe_lsss::compression_enabled() << std::endl;

  ::testing::InitGoogleTest(&argc, argv);
  rc = RUN_ALL_TESTS();

  abe_lsss::shutdown();

  return rc;
}
