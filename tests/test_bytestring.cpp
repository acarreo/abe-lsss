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
