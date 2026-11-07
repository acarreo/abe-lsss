#include <abe_lsss/abe.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace {

bool roundTrip(abe_lsss::Scheme scheme, const std::string& encryptionInput,
               const std::string& keyInput, std::size_t plaintextSize = 32) {
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
  for (std::size_t i = 0; i < plaintextSize; ++i) {
    plaintext.push_back(static_cast<std::uint8_t>(i));
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
  EXPECT_NE(abe_lsss::create_hybrid_context(abe_lsss::cp_waters), nullptr);
  EXPECT_NE(abe_lsss::create_hybrid_context(abe_lsss::kp_gpsw), nullptr);
  EXPECT_EQ(abe_lsss::create_hybrid_context(static_cast<abe_lsss::Scheme>(250)),
            nullptr);
}

TEST(AbeLsssApi, WatersCpAbeRoundTrip) {
  EXPECT_TRUE(roundTrip(abe_lsss::cp_waters, "(Engineering and ProjectA)",
                        "Engineering|ProjectA"));
}

TEST(AbeLsssApi, GpswKpAbeRoundTrip) {
  EXPECT_TRUE(roundTrip(abe_lsss::kp_gpsw, "Engineering|ProjectA",
                        "(Engineering and (ProjectA or ProjectB))"));
}

TEST(AbeLsssApi, LongMessageRoundTripsForBothSchemes) {
  constexpr std::size_t messageSize = 10 * 1024;
  EXPECT_TRUE(roundTrip(abe_lsss::cp_waters, "(Engineering and ProjectA)",
                        "Engineering|ProjectA", messageSize));
  EXPECT_TRUE(roundTrip(abe_lsss::kp_gpsw, "Engineering|ProjectA",
                        "(Engineering and (ProjectA or ProjectB))",
                        messageSize));
}

TEST(AbeLsssApi, AesGcmAliasesRoundTrip) {
  auto key = std::make_shared<abe_lsss::SymmetricKey>();
  ASSERT_TRUE(key->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES));
  abe_lsss::ByteString iv, ciphertext, tag;
  const std::string plaintext = "AES-GCM aliases";

  abe_lsss::AesGcm cipher(DEFAULT_AES_SEC_LEVEL, key->getKeyBytes());
  ASSERT_EQ(cipher.encrypt(plaintext, iv, ciphertext, tag), OpenABE_NOERROR);
  std::string recovered;
  ASSERT_TRUE(cipher.decrypt(recovered, iv, ciphertext, tag));
  EXPECT_EQ(recovered, plaintext);

  abe_lsss::ByteString input, streamIv, streamCiphertext, streamTag, output;
  input.fromString(plaintext);
  abe_lsss::AesGcmStream encryptor(DEFAULT_AES_SEC_LEVEL, key);
  ASSERT_EQ(encryptor.encryptInit(streamIv), OpenABE_NOERROR);
  ASSERT_EQ(encryptor.encryptUpdate(input, streamCiphertext), OpenABE_NOERROR);
  ASSERT_EQ(encryptor.encryptFinalize(streamCiphertext, streamTag), OpenABE_NOERROR);
  abe_lsss::AesGcmStream decryptor(DEFAULT_AES_SEC_LEVEL, key);
  ASSERT_EQ(decryptor.decryptInit(streamIv, streamTag), OpenABE_NOERROR);
  ASSERT_EQ(decryptor.decryptUpdate(streamCiphertext, output), OpenABE_NOERROR);
  ASSERT_EQ(decryptor.decryptFinalize(output), OpenABE_NOERROR);
  EXPECT_EQ(output, input);
}

TEST(AbeLsssApi, HybridRoundTripsAndRejectsTampering) {
  for (auto scheme : {abe_lsss::cp_waters, abe_lsss::kp_gpsw}) {
    SCOPED_TRACE(scheme);
    auto context = abe_lsss::create_hybrid_context(scheme);
    ASSERT_TRUE(context);
    ASSERT_EQ(context->generateParams("mpk", "msk"), OpenABE_NOERROR);
    auto policy = abe_lsss::parse_policy("(Engineering and ProjectA)");
    auto attributes = abe_lsss::parse_attributes("Engineering|ProjectA");
    auto missingAttributes = abe_lsss::parse_attributes("Engineering");
    ASSERT_TRUE(policy && attributes && missingAttributes);
    auto* keyInput = scheme == abe_lsss::cp_waters ? attributes.get() : policy.get();
    auto* encInput = scheme == abe_lsss::cp_waters ? policy.get() : attributes.get();
    ASSERT_EQ(context->keygen(keyInput, "alice", "mpk", "msk"), OpenABE_NOERROR);
    abe_lsss::ByteString mpkBlob, userBlob;
    ASSERT_EQ(context->exportKey("mpk", mpkBlob), OpenABE_NOERROR);
    ASSERT_EQ(context->exportKey("alice", userBlob), OpenABE_NOERROR);
    auto recipient = abe_lsss::create_hybrid_context(scheme);
    ASSERT_TRUE(recipient);
    ASSERT_EQ(recipient->loadMasterPublicParams("mpk", mpkBlob), OpenABE_NOERROR);
    ASSERT_EQ(recipient->loadUserSecretParams("alice", userBlob), OpenABE_NOERROR);
    if (scheme == abe_lsss::cp_waters) {
      ASSERT_EQ(context->keygen(missingAttributes.get(), "bob", "mpk", "msk"),
                OpenABE_NOERROR);
    } else {
      auto missingPolicy = abe_lsss::parse_policy("(Engineering and Missing)");
      ASSERT_TRUE(missingPolicy);
      ASSERT_EQ(context->keygen(missingPolicy.get(), "bob", "mpk", "msk"),
                OpenABE_NOERROR);
    }

    abe_lsss::Ciphertext ciphertext;
    for (std::size_t size : {std::size_t{0}, std::size_t{1}, std::size_t{32},
                             std::size_t{10000}}) {
      SCOPED_TRACE(size);
      abe_lsss::ByteString plaintext, recovered;
      for (std::size_t i = 0; i < size; ++i) {
        plaintext.push_back(static_cast<std::uint8_t>(i));
      }
      ASSERT_EQ(context->encrypt("mpk", encInput, plaintext, ciphertext),
                OpenABE_NOERROR);
      abe_lsss::ByteString serialized;
      ciphertext.exportToBytes(serialized);
      abe_lsss::Ciphertext loaded;
      loaded.loadFromBytes(serialized);
      ASSERT_EQ(context->decrypt("mpk", "alice", recovered, loaded), OpenABE_NOERROR);
      EXPECT_EQ(recovered, plaintext);
      recovered.clear();
      ASSERT_EQ(recipient->decrypt("mpk", "alice", recovered, loaded), OpenABE_NOERROR);
      EXPECT_EQ(recovered, plaintext);

      recovered.fromString("previous");
      EXPECT_NE(context->decrypt("mpk", "bob", recovered, loaded), OpenABE_NOERROR);
      EXPECT_TRUE(recovered.empty());

      for (const char* name : {"_GCM_IV", "_GCM_TAG", "_GCM_CT"}) {
        auto* component = loaded.getByteString(name);
        ASSERT_NE(component, nullptr);
        if (component->empty()) {
          continue;
        }
        component->at(0) ^= 1;
        recovered.fromString("previous");
        EXPECT_EQ(context->decrypt("mpk", "alice", recovered, loaded),
                  OpenABE_ERROR_DECRYPTION_FAILED);
        EXPECT_TRUE(recovered.empty());
        component->at(0) ^= 1;
      }
      loaded.getUID().at(0) ^= 1;
      recovered.fromString("previous");
      EXPECT_EQ(context->decrypt("mpk", "alice", recovered, loaded),
                OpenABE_ERROR_DECRYPTION_FAILED);
      EXPECT_TRUE(recovered.empty());
      loaded.getUID().at(0) ^= 1;
      loaded.setSchemeType(scheme == abe_lsss::cp_waters
                               ? abe_lsss::kp_gpsw : abe_lsss::cp_waters);
      EXPECT_EQ(context->decrypt("mpk", "alice", recovered, loaded),
                OpenABE_ERROR_INVALID_CIPHERTEXT_HEADER);
      EXPECT_TRUE(recovered.empty());

      loaded.loadFromBytes(serialized);
      if (scheme == abe_lsss::cp_waters) {
        G1 replacement;
        replacement.setGenerator();
        loaded.setComponent("Cprime", &replacement);
      } else {
        G2 replacement;
        replacement.setGenerator();
        loaded.setComponent("Cpr2", &replacement);
      }
      recovered.fromString("previous");
      EXPECT_EQ(context->decrypt("mpk", "alice", recovered, loaded),
                OpenABE_ERROR_DECRYPTION_FAILED);
      EXPECT_TRUE(recovered.empty());
    }
  }
}

TEST(AbeLsssApi, HybridRejectsMalformedKpKemComponents) {
  auto context = abe_lsss::create_hybrid_context(abe_lsss::kp_gpsw);
  ASSERT_TRUE(context);
  ASSERT_EQ(context->generateParams("mpk", "msk"), OpenABE_NOERROR);
  auto policy = abe_lsss::parse_policy("(A and B)");
  auto attributes = abe_lsss::parse_attributes("A|B");
  ASSERT_TRUE(policy && attributes);
  ASSERT_EQ(context->keygen(policy.get(), "alice", "mpk", "msk"), OpenABE_NOERROR);
  abe_lsss::ByteString input, output;
  input.fromString("message");
  abe_lsss::Ciphertext ciphertext;
  ASSERT_EQ(context->encrypt("mpk", attributes.get(), input, ciphertext), OpenABE_NOERROR);
  abe_lsss::ByteString wrongType;
  wrongType.fromString("not an attribute list");
  ciphertext.setComponent("attributes", &wrongType);
  output.fromString("previous");
  EXPECT_NE(context->decrypt("mpk", "alice", output, ciphertext), OpenABE_NOERROR);
  EXPECT_TRUE(output.empty());

  ASSERT_EQ(context->encrypt("mpk", attributes.get(), input, ciphertext), OpenABE_NOERROR);
  for (const auto& name : ciphertext.getKeys()) {
    if (name.rfind("C_", 0) == 0) {
      ciphertext.setComponent(name, &wrongType);
    }
  }
  output.fromString("previous");
  EXPECT_NE(context->decrypt("mpk", "alice", output, ciphertext), OpenABE_NOERROR);
  EXPECT_TRUE(output.empty());
}

TEST(AbeLsssApi, HybridStreamingRoundTripAndOneShotCompatibility) {
  for (auto scheme : {abe_lsss::cp_waters, abe_lsss::kp_gpsw}) {
    SCOPED_TRACE(scheme);
    auto context = abe_lsss::create_hybrid_context(scheme);
    ASSERT_TRUE(context);
    ASSERT_EQ(context->generateParams("mpk", "msk"), OpenABE_NOERROR);
    auto policy = abe_lsss::parse_policy("(A and B)");
    auto attributes = abe_lsss::parse_attributes("A|B");
    ASSERT_TRUE(policy && attributes);
    auto* keyInput = scheme == abe_lsss::cp_waters ? attributes.get() : policy.get();
    auto* encInput = scheme == abe_lsss::cp_waters ? policy.get() : attributes.get();
    ASSERT_EQ(context->keygen(keyInput, "alice", "mpk", "msk"), OpenABE_NOERROR);

    abe_lsss::Ciphertext kem;
    abe_lsss::ByteString iv, tag, message, encrypted, block, recovered;
    for (std::size_t i = 0; i < 131101; ++i) {
      message.push_back(static_cast<std::uint8_t>(i));
    }
    std::unique_ptr<abe_lsss::HybridEncryptStream> enc;
    ASSERT_EQ(context->encryptInit("mpk", encInput, kem, iv, enc), OpenABE_NOERROR);
    ASSERT_TRUE(enc);
    EXPECT_EQ(context->encryptInit("mpk", encInput, kem, iv, enc),
              OpenABE_ERROR_IN_USE_ALREADY);
    abe_lsss::ByteString empty;
    ASSERT_EQ(enc->update(empty, block), OpenABE_NOERROR);
    EXPECT_TRUE(block.empty());
    for (std::size_t offset = 0; offset < message.size(); offset += 9973) {
      auto chunk = message.getSubset(offset, std::min<std::size_t>(9973, message.size() - offset));
      ASSERT_EQ(enc->update(chunk, block), OpenABE_NOERROR);
      encrypted += block;
    }
    ASSERT_EQ(enc->finalize(tag), OpenABE_NOERROR);
    EXPECT_EQ(enc->update(empty, block), OpenABE_ERROR_INVALID_CONTEXT);
    EXPECT_EQ(enc->finalize(block), OpenABE_ERROR_INVALID_CONTEXT);

    abe_lsss::ByteString blob;
    kem.exportToBytes(blob);
    abe_lsss::Ciphertext loaded;
    loaded.loadFromBytes(blob);
    std::unique_ptr<abe_lsss::HybridDecryptStream> dec;
    ASSERT_EQ(context->decryptInit("mpk", "alice", loaded, iv, dec), OpenABE_NOERROR);
    EXPECT_EQ(context->decryptInit("mpk", "alice", loaded, iv, dec),
              OpenABE_ERROR_IN_USE_ALREADY);
    for (std::size_t offset = 0; offset < encrypted.size(); offset += 5003) {
      auto chunk = encrypted.getSubset(offset, std::min<std::size_t>(5003, encrypted.size() - offset));
      ASSERT_EQ(dec->update(chunk, block), OpenABE_NOERROR);
      recovered += block;
    }
    ASSERT_EQ(dec->finalize(tag), OpenABE_NOERROR);
    EXPECT_EQ(recovered, message);
    EXPECT_EQ(dec->update(empty, block), OpenABE_ERROR_INVALID_CONTEXT);
    EXPECT_EQ(dec->finalize(tag), OpenABE_ERROR_INVALID_CONTEXT);

    loaded.setComponent("_GCM_IV", &iv);
    loaded.setComponent("_GCM_CT", &encrypted);
    loaded.setComponent("_GCM_TAG", &tag);
    ASSERT_EQ(context->decrypt("mpk", "alice", recovered, loaded), OpenABE_NOERROR);
    EXPECT_EQ(recovered, message);

    abe_lsss::Ciphertext oneShot;
    ASSERT_EQ(context->encrypt("mpk", encInput, message, oneShot), OpenABE_NOERROR);
    auto* oneIv = oneShot.getByteString("_GCM_IV");
    auto* onePayload = oneShot.getByteString("_GCM_CT");
    auto* oneTag = oneShot.getByteString("_GCM_TAG");
    ASSERT_TRUE(oneIv && onePayload && oneTag);
    dec.reset();
    ASSERT_EQ(context->decryptInit("mpk", "alice", oneShot, *oneIv, dec), OpenABE_NOERROR);
    ASSERT_EQ(dec->update(*onePayload, recovered), OpenABE_NOERROR);
    ASSERT_EQ(dec->finalize(*oneTag), OpenABE_NOERROR);
    EXPECT_EQ(recovered, message);
  }
}

TEST(AbeLsssApi, HybridStreamingAuthenticationAndEmptyMessages) {
  auto context = abe_lsss::create_hybrid_context(abe_lsss::cp_waters);
  ASSERT_TRUE(context);
  ASSERT_EQ(context->generateParams("mpk", "msk"), OpenABE_NOERROR);
  auto policy = abe_lsss::parse_policy("(A and B)");
  auto attributes = abe_lsss::parse_attributes("A|B");
  ASSERT_TRUE(policy && attributes);
  ASSERT_EQ(context->keygen(attributes.get(), "alice", "mpk", "msk"), OpenABE_NOERROR);
  abe_lsss::Ciphertext kem;
  abe_lsss::ByteString iv, tag, plaintext, ciphertext, block;
  std::unique_ptr<abe_lsss::HybridEncryptStream> enc;
  ASSERT_EQ(context->encryptInit("mpk", policy.get(), kem, iv, enc), OpenABE_NOERROR);
  ASSERT_EQ(enc->finalize(tag), OpenABE_NOERROR);
  std::unique_ptr<abe_lsss::HybridDecryptStream> dec;
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem, iv, dec), OpenABE_NOERROR);
  ASSERT_EQ(dec->finalize(tag), OpenABE_NOERROR);

  enc.reset();
  plaintext.fromString("secret payload");
  ASSERT_EQ(context->encryptInit("mpk", policy.get(), kem, iv, enc), OpenABE_NOERROR);
  EXPECT_EQ(enc->update(plaintext, plaintext), OpenABE_ERROR_INVALID_INPUT);
  ASSERT_EQ(enc->update(plaintext, ciphertext), OpenABE_NOERROR);
  ASSERT_EQ(enc->finalize(tag), OpenABE_NOERROR);
  for (int alteration = 0; alteration < 5; ++alteration) {
    SCOPED_TRACE(alteration);
    dec.reset();
    const auto lastByte = ciphertext.back();
    if (alteration == 0) ciphertext[0] ^= 1;
    if (alteration == 1) iv[0] ^= 1;
    if (alteration == 2) tag[0] ^= 1;
    if (alteration == 3) kem.getUID()[0] ^= 1;
    if (alteration == 4) ciphertext.pop_back();
    ASSERT_EQ(context->decryptInit("mpk", "alice", kem, iv, dec), OpenABE_NOERROR);
    ASSERT_EQ(dec->update(ciphertext, block), OpenABE_NOERROR);
    EXPECT_EQ(dec->finalize(tag), OpenABE_ERROR_DECRYPTION_FAILED);
    EXPECT_EQ(dec->finalize(tag), OpenABE_ERROR_INVALID_CONTEXT);
    if (alteration == 0) ciphertext[0] ^= 1;
    if (alteration == 1) iv[0] ^= 1;
    if (alteration == 2) tag[0] ^= 1;
    if (alteration == 3) kem.getUID()[0] ^= 1;
    if (alteration == 4) ciphertext.push_back(lastByte);
  }
  dec.reset();
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem, iv, dec), OpenABE_NOERROR);
  tag.pop_back();
  EXPECT_EQ(dec->finalize(tag), OpenABE_ERROR_INVALID_TAG_LENGTH);
  EXPECT_EQ(dec->finalize(tag), OpenABE_ERROR_INVALID_CONTEXT);
  dec.reset();
  auto shortIv = iv;
  shortIv.pop_back();
  EXPECT_EQ(context->decryptInit("mpk", "alice", kem, shortIv, dec),
            OpenABE_ERROR_INVALID_CIPHERTEXT);
  EXPECT_FALSE(dec);
  EXPECT_NE(context->decryptInit("mpk", "missing", kem, iv, dec), OpenABE_NOERROR);
  EXPECT_FALSE(dec);

  tag.push_back(0);
  enc.reset();
  ASSERT_EQ(context->encryptInit("mpk", policy.get(), kem, iv, enc), OpenABE_NOERROR);
  ASSERT_EQ(enc->update(plaintext, ciphertext), OpenABE_NOERROR);
  ASSERT_EQ(enc->finalize(tag), OpenABE_NOERROR);
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem, iv, dec), OpenABE_NOERROR);
  context.reset();
  ASSERT_EQ(dec->update(ciphertext, block), OpenABE_NOERROR);
  EXPECT_EQ(dec->finalize(tag), OpenABE_NOERROR);
  EXPECT_EQ(block, plaintext);
}

TEST(AbeLsssApi, DISABLED_HybridStreamingOneGiB) {
  auto context = abe_lsss::create_hybrid_context(abe_lsss::cp_waters);
  ASSERT_TRUE(context);
  ASSERT_EQ(context->generateParams("mpk", "msk"), OpenABE_NOERROR);
  auto policy = abe_lsss::parse_policy("(A and B)");
  auto attributes = abe_lsss::parse_attributes("A|B");
  ASSERT_TRUE(policy && attributes);
  ASSERT_EQ(context->keygen(attributes.get(), "alice", "mpk", "msk"), OpenABE_NOERROR);

  abe_lsss::Ciphertext kem;
  abe_lsss::ByteString input, iv, tag, encrypted, recovered;
  input.resize(1024 * 1024);
  for (std::size_t i = 0; i < input.size(); ++i) {
    input[i] = static_cast<std::uint8_t>(i);
  }
  std::unique_ptr<abe_lsss::HybridEncryptStream> enc;
  std::unique_ptr<abe_lsss::HybridDecryptStream> dec;
  ASSERT_EQ(context->encryptInit("mpk", policy.get(), kem, iv, enc), OpenABE_NOERROR);
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem, iv, dec), OpenABE_NOERROR);
  bool allMatch = true;
  for (int i = 0; i < 1024; ++i) {
    ASSERT_EQ(enc->update(input, encrypted), OpenABE_NOERROR);
    ASSERT_EQ(dec->update(encrypted, recovered), OpenABE_NOERROR);
    allMatch = allMatch && (recovered == input);
  }
  ASSERT_EQ(enc->finalize(tag), OpenABE_NOERROR);
  ASSERT_EQ(dec->finalize(tag), OpenABE_NOERROR);
  EXPECT_TRUE(allMatch);
}

TEST(AbeLsssApi, HybridRejectsMissingAndInvalidComponents) {
  auto context = abe_lsss::create_hybrid_context(abe_lsss::cp_waters);
  ASSERT_EQ(context->generateParams("mpk", "msk"), OpenABE_NOERROR);
  auto policy = abe_lsss::parse_policy("(A and B)");
  auto attributes = abe_lsss::parse_attributes("A|B");
  ASSERT_TRUE(policy && attributes);
  ASSERT_EQ(context->keygen(attributes.get(), "alice", "mpk", "msk"),
            OpenABE_NOERROR);
  abe_lsss::ByteString input, output;
  input.fromString("message");
  abe_lsss::Ciphertext ciphertext;
  ASSERT_EQ(context->encrypt("mpk", policy.get(), input, ciphertext), OpenABE_NOERROR);
  auto* tag = ciphertext.getByteString("_GCM_TAG");
  ASSERT_NE(tag, nullptr);
  tag->pop_back();
  output.fromString("previous");
  EXPECT_EQ(context->decrypt("mpk", "alice", output, ciphertext),
            OpenABE_ERROR_INVALID_CIPHERTEXT);
  EXPECT_TRUE(output.empty());
  ASSERT_EQ(ciphertext.deleteComponent("_GCM_IV"), OpenABE_NOERROR);
  EXPECT_NE(context->decrypt("mpk", "alice", output, ciphertext), OpenABE_NOERROR);
  EXPECT_TRUE(output.empty());
  abe_lsss::ByteString malformedBlob;
  EXPECT_NO_THROW(ciphertext.exportToBytes(malformedBlob));

  ASSERT_EQ(context->encrypt("mpk", policy.get(), input, ciphertext), OpenABE_NOERROR);
  abe_lsss::ByteString firstIv = *ciphertext.getByteString("_GCM_IV");
  ASSERT_EQ(context->encrypt("mpk", policy.get(), input, ciphertext), OpenABE_NOERROR);
  EXPECT_NE(firstIv, *ciphertext.getByteString("_GCM_IV"));
  auto* iv = ciphertext.getByteString("_GCM_IV");
  iv->pop_back();
  EXPECT_EQ(context->decrypt("mpk", "alice", output, ciphertext),
            OpenABE_ERROR_INVALID_CIPHERTEXT);
  EXPECT_TRUE(output.empty());
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
