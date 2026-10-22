#include <abe_lsss/abe.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <string>

namespace {

bool roundTrip(abe_lsss::Scheme scheme, const std::string& encryptionInput,
               const std::string& keyInput) {
  auto context = abe_lsss::create_context(scheme);
  if (!context ||
      context->generateParams("api_mpk", "api_msk") != OpenABE_NOERROR) {
    return false;
  }

  auto encInput = scheme == abe_lsss::cp_waters
      ? abe_lsss::parse_policy(encryptionInput)
      : abe_lsss::parse_attributes(encryptionInput);
  auto keyInputParsed = scheme == abe_lsss::cp_waters
      ? abe_lsss::parse_attributes(keyInput)
      : abe_lsss::parse_policy(keyInput);
  if (!encInput || !keyInputParsed ||
      context->keygen(keyInputParsed.get(), "api_user", "api_mpk", "api_msk") !=
          OpenABE_NOERROR) {
    return false;
  }

  abe_lsss::ByteString plaintext, recovered;
  for (std::uint8_t byte = 0; byte < 32; ++byte) {
    plaintext.push_back(byte);
  }
  abe_lsss::Ciphertext ciphertext;
  return context->encrypt("api_mpk", encInput.get(), plaintext, ciphertext) ==
             OpenABE_NOERROR &&
         context->decrypt("api_mpk", "api_user", recovered, ciphertext) ==
             OpenABE_NOERROR &&
         plaintext == recovered;
}

}

TEST(AbeLsssApi, CompressionOptionCanBeChanged) {
  EXPECT_TRUE(abe_lsss::compression_enabled());
  abe_lsss::set_compression(false);
  EXPECT_FALSE(abe_lsss::compression_enabled());
  abe_lsss::set_compression(true);
  EXPECT_TRUE(abe_lsss::compression_enabled());
}

TEST(AbeLsssApi, InitializationRejectsDuplicateCalls) {
  EXPECT_THROW(abe_lsss::initialize(), std::runtime_error);
}

TEST(AbeLsssApi, CreatesOnlySupportedSchemes) {
  EXPECT_NE(abe_lsss::create_context(abe_lsss::cp_waters), nullptr);
  EXPECT_NE(abe_lsss::create_context(abe_lsss::kp_gpsw), nullptr);
  EXPECT_EQ(abe_lsss::create_context(static_cast<abe_lsss::Scheme>(250)), nullptr);
}

TEST(AbeLsssApi, WatersCpAbeRoundTrip) {
  EXPECT_TRUE(roundTrip(abe_lsss::cp_waters, "(Engineering and ProjectA)",
                        "Engineering|ProjectA"));
}

TEST(AbeLsssApi, GpswKpAbeRoundTrip) {
  EXPECT_TRUE(roundTrip(abe_lsss::kp_gpsw, "Engineering|ProjectA",
                        "(Engineering and (ProjectA or ProjectB))"));
}

TEST(AbeLsssApi, GroupElementSerializationRoundTrips) {
  G1 g1;
  g1.setGenerator();
  abe_lsss::ByteString g1Blob;
  g1.serialize(g1Blob);
  G1 restoredG1;
  restoredG1.deserialize(g1Blob);
  EXPECT_TRUE(g1 == restoredG1);

  G2 g2;
  g2.setGenerator();
  abe_lsss::ByteString g2Blob;
  g2.serialize(g2Blob);
  G2 restoredG2;
  restoredG2.deserialize(g2Blob);
  EXPECT_TRUE(g2 == restoredG2);

  GT gt;
  gt.setGenerator();
  abe_lsss::ByteString gtBlob;
  gt.serialize(gtBlob);
  GT restoredGt;
  restoredGt.deserialize(gtBlob);
  EXPECT_TRUE(gt == restoredGt);
}

int main(int argc, char** argv) {
  abe_lsss::initialize();
  ::testing::InitGoogleTest(&argc, argv);
  const int result = RUN_ALL_TESTS();
  abe_lsss::shutdown();
  return result;
}
