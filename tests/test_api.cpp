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

namespace {

// Malformed blobs must be handled through an error code or an exception and
// must never crash or terminate the process. The CPA contexts do not
// authenticate ciphertexts (the payload is masked by XOR), so a modified
// ciphertext may decrypt to garbage; only truncation is required to be rejected.
enum class Outcome { Rejected, Correct, Wrong };

template <typename Fn>
Outcome classify(Fn&& attempt, const abe_lsss::ByteString& expected) {
  abe_lsss::ByteString recovered;
  try {
    if (attempt(recovered) != OpenABE_NOERROR) return Outcome::Rejected;
  } catch (const std::exception&) {
    return Outcome::Rejected;
  } catch (const OpenABE_ERROR&) {
    return Outcome::Rejected;
  }
  return recovered == expected ? Outcome::Correct : Outcome::Wrong;
}

}

TEST(AbeLsssApi, MalformedCiphertextIsHandledWithoutCrashing) {
  auto context = abe_lsss::create_context(abe_lsss::cp_waters);
  ASSERT_EQ(context->generateParams("mal_mpk", "mal_msk"), OpenABE_NOERROR);
  auto attrs = abe_lsss::parse_attributes("A|B");
  auto policy = abe_lsss::parse_policy("(A and B)");
  ASSERT_TRUE(attrs && policy);
  ASSERT_EQ(context->keygen(attrs.get(), "mal_user", "mal_mpk", "mal_msk"),
            OpenABE_NOERROR);

  abe_lsss::ByteString plaintext, blob;
  for (std::uint8_t byte = 0; byte < 32; ++byte) plaintext.push_back(byte);
  abe_lsss::Ciphertext ciphertext;
  ASSERT_EQ(context->encrypt("mal_mpk", policy.get(), plaintext, ciphertext),
            OpenABE_NOERROR);
  ciphertext.exportToBytes(blob);

  auto decryptBlob = [&](abe_lsss::ByteString candidate) {
    return classify(
        [&](abe_lsss::ByteString& out) {
          abe_lsss::Ciphertext ct;
          ct.loadFromBytes(candidate);
          return context->decrypt("mal_mpk", "mal_user", out, ct);
        },
        plaintext);
  };

  ASSERT_EQ(decryptBlob(blob), Outcome::Correct);

  const size_t step = blob.size() > 400 ? blob.size() / 200 : 1;
  for (size_t cut = 0; cut < blob.size(); cut += step) {
    EXPECT_NE(decryptBlob(blob.getSubset(0, cut)), Outcome::Wrong) << "cut=" << cut;
  }
  for (size_t i = 0; i < blob.size(); i += step) {
    abe_lsss::ByteString flipped = blob;
    flipped[i] ^= 0x01;
    decryptBlob(flipped);
  }
}

TEST(AbeLsssApi, MalformedKeyBlobsDoNotCrashLoaders) {
  auto context = abe_lsss::create_context(abe_lsss::cp_waters);
  ASSERT_EQ(context->generateParams("key_mpk", "key_msk"), OpenABE_NOERROR);
  auto attrs = abe_lsss::parse_attributes("A|B");
  ASSERT_TRUE(attrs);
  ASSERT_EQ(context->keygen(attrs.get(), "key_user", "key_mpk", "key_msk"),
            OpenABE_NOERROR);

  abe_lsss::ByteString mpk, sk;
  ASSERT_EQ(context->exportKey("key_mpk", mpk), OpenABE_NOERROR);
  ASSERT_EQ(context->exportKey("key_user", sk), OpenABE_NOERROR);

  auto tryLoad = [&](bool isMpk, abe_lsss::ByteString blob) {
    try {
      return isMpk ? context->loadMasterPublicParams("bad_mpk", blob)
                   : context->loadUserSecretParams("bad_sk", blob);
    } catch (const std::exception&) {
    } catch (const OpenABE_ERROR&) {
    }
    return OpenABE_ERROR_INVALID_INPUT;
  };

  for (bool isMpk : {true, false}) {
    abe_lsss::ByteString good = isMpk ? mpk : sk;
    const size_t step = good.size() > 400 ? good.size() / 200 : 1;
    for (size_t cut = 0; cut < good.size(); cut += step) {
      tryLoad(isMpk, good.getSubset(0, cut));
    }
    for (size_t i = 0; i < good.size(); i += step) {
      abe_lsss::ByteString flipped = good;
      flipped[i] ^= 0x80;
      tryLoad(isMpk, flipped);
    }
  }
}

int main(int argc, char** argv) {
  abe_lsss::initialize();
  ::testing::InitGoogleTest(&argc, argv);
  const int result = RUN_ALL_TESTS();
  abe_lsss::shutdown();
  return result;
}
