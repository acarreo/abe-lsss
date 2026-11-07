#include <abe_lsss/abe.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>

namespace {

class HybridTest : public ::testing::TestWithParam<abe_lsss::Scheme> {
protected:
  void SetUp() override {
    context = abe_lsss::create_hybrid_context(GetParam());
    ASSERT_TRUE(context);
    policy = abe_lsss::parse_policy("(Engineering and ProjectA)");
    attributes = abe_lsss::parse_attributes("Engineering|ProjectA");
    ASSERT_TRUE(policy && attributes);
    ASSERT_EQ(context->generateParams("mpk", "msk"), OpenABE_NOERROR);
    auto* keyInput = GetParam() == abe_lsss::cp_waters
        ? attributes.get() : policy.get();
    ASSERT_EQ(context->keygen(keyInput, "alice", "mpk", "msk"), OpenABE_NOERROR);
  }

  const abe_lsss::FunctionInput* encryptionInput() const {
    return GetParam() == abe_lsss::cp_waters ? policy.get() : attributes.get();
  }

  std::unique_ptr<abe_lsss::HybridContext> context;
  std::unique_ptr<abe_lsss::FunctionInput> policy;
  std::unique_ptr<abe_lsss::FunctionInput> attributes;
};

TEST_P(HybridTest, OneShotHandlesBinaryBoundaryLengths) {
  for (std::size_t length : {0u, 1u, 15u, 16u, 17u, 255u, 256u,
                             65535u, 65536u, 65537u}) {
    SCOPED_TRACE(length);
    abe_lsss::ByteString input, output;
    for (std::size_t i = 0; i < length; ++i) {
      input.push_back(static_cast<std::uint8_t>(i));
    }
    abe_lsss::Ciphertext ciphertext;
    ASSERT_EQ(context->encrypt("mpk", encryptionInput(), input, ciphertext),
              OpenABE_NOERROR);
    ASSERT_EQ(context->decrypt("mpk", "alice", output, ciphertext),
              OpenABE_NOERROR);
    EXPECT_EQ(output, input);
  }
}

TEST_P(HybridTest, RejectsCiphertextFromDifferentAuthority) {
  auto other = abe_lsss::create_hybrid_context(GetParam());
  ASSERT_TRUE(other);
  ASSERT_EQ(other->generateParams("mpk", "msk"), OpenABE_NOERROR);
  auto* keyInput = GetParam() == abe_lsss::cp_waters
      ? attributes.get() : policy.get();
  ASSERT_EQ(other->keygen(keyInput, "alice", "mpk", "msk"), OpenABE_NOERROR);
  abe_lsss::ByteString input, output;
  input.fromString("authenticated payload");
  output.fromString("previous plaintext");
  abe_lsss::Ciphertext ciphertext;
  ASSERT_EQ(context->encrypt("mpk", encryptionInput(), input, ciphertext),
            OpenABE_NOERROR);
  EXPECT_NE(other->decrypt("mpk", "alice", output, ciphertext), OpenABE_NOERROR);
  EXPECT_TRUE(output.empty());
}

TEST_P(HybridTest, RejectsMissingAndWrongTypePayloadComponents) {
  abe_lsss::ByteString input, output, serialized;
  input.fromString("payload");
  abe_lsss::Ciphertext original;
  ASSERT_EQ(context->encrypt("mpk", encryptionInput(), input, original),
            OpenABE_NOERROR);
  original.exportToBytes(serialized);
  for (const char* name : {"_GCM_IV", "_GCM_CT", "_GCM_TAG"}) {
    SCOPED_TRACE(name);
    abe_lsss::Ciphertext missing;
    missing.loadFromBytes(serialized);
    ASSERT_EQ(missing.deleteComponent(name), OpenABE_NOERROR);
    output.fromString("previous plaintext");
    EXPECT_NE(context->decrypt("mpk", "alice", output, missing), OpenABE_NOERROR);
    EXPECT_TRUE(output.empty());

    abe_lsss::Ciphertext wrongType;
    wrongType.loadFromBytes(serialized);
    OpenABEUInteger integer(1);
    wrongType.setComponent(name, &integer);
    output.fromString("previous plaintext");
    EXPECT_NE(context->decrypt("mpk", "alice", output, wrongType), OpenABE_NOERROR);
    EXPECT_TRUE(output.empty());
  }
}

TEST_P(HybridTest, RejectsModifiedCiphertextHeaderAndPayload) {
  abe_lsss::ByteString input, output, serialized;
  input.fromString("authenticated payload");
  abe_lsss::Ciphertext original;
  ASSERT_EQ(context->encrypt("mpk", encryptionInput(), input, original),
            OpenABE_NOERROR);
  original.exportToBytes(serialized);

  for (const char* name : {"_GCM_IV", "_GCM_CT", "_GCM_TAG"}) {
    SCOPED_TRACE(name);
    abe_lsss::Ciphertext altered;
    altered.loadFromBytes(serialized);
    auto* component = altered.getByteString(name);
    ASSERT_TRUE(component && !component->empty());
    component->back() ^= 0x80;
    output.fromString("previous plaintext");
    EXPECT_EQ(context->decrypt("mpk", "alice", output, altered),
              OpenABE_ERROR_DECRYPTION_FAILED);
    EXPECT_TRUE(output.empty());
  }

  abe_lsss::Ciphertext altered;
  altered.loadFromBytes(serialized);
  altered.getUID().back() ^= 0x80;
  output.fromString("previous plaintext");
  EXPECT_EQ(context->decrypt("mpk", "alice", output, altered),
            OpenABE_ERROR_DECRYPTION_FAILED);
  EXPECT_TRUE(output.empty());
}

TEST_P(HybridTest, StreamingRejectsReorderedDuplicatedAndTruncatedBlocks) {
  abe_lsss::Ciphertext kem;
  abe_lsss::ByteString iv, tag, first, second, cipher1, cipher2, output;
  first.fromString("first block!");
  second.fromString("second block");
  std::unique_ptr<abe_lsss::HybridEncryptStream> encryptor;
  ASSERT_EQ(context->encryptInit("mpk", encryptionInput(), kem, iv, encryptor),
            OpenABE_NOERROR);
  ASSERT_EQ(encryptor->update(first, cipher1), OpenABE_NOERROR);
  ASSERT_EQ(encryptor->update(second, cipher2), OpenABE_NOERROR);
  ASSERT_EQ(encryptor->finalize(tag), OpenABE_NOERROR);

  for (int alteration = 0; alteration < 3; ++alteration) {
    SCOPED_TRACE(alteration);
    std::unique_ptr<abe_lsss::HybridDecryptStream> decryptor;
    ASSERT_EQ(context->decryptInit("mpk", "alice", kem, iv, decryptor),
              OpenABE_NOERROR);
    if (alteration == 0) {
      ASSERT_EQ(decryptor->update(cipher2, output), OpenABE_NOERROR);
      ASSERT_EQ(decryptor->update(cipher1, output), OpenABE_NOERROR);
    } else {
      ASSERT_EQ(decryptor->update(cipher1, output), OpenABE_NOERROR);
      if (alteration == 1) {
        ASSERT_EQ(decryptor->update(cipher1, output), OpenABE_NOERROR);
        ASSERT_EQ(decryptor->update(cipher2, output), OpenABE_NOERROR);
      }
    }
    EXPECT_EQ(decryptor->finalize(tag), OpenABE_ERROR_DECRYPTION_FAILED);
    EXPECT_EQ(decryptor->update(cipher1, output), OpenABE_ERROR_INVALID_CONTEXT);
  }
}

TEST_P(HybridTest, StreamsRemainIndependentAndOutputIsReplaced) {
  abe_lsss::Ciphertext kem1, kem2;
  abe_lsss::ByteString iv1, iv2, tag1, tag2, input1, input2, ct1, ct2, output;
  input1.fromString("first message");
  input2.fromString("other message");
  std::unique_ptr<abe_lsss::HybridEncryptStream> enc1, enc2;
  ASSERT_EQ(context->encryptInit("mpk", encryptionInput(), kem1, iv1, enc1),
            OpenABE_NOERROR);
  ASSERT_EQ(context->encryptInit("mpk", encryptionInput(), kem2, iv2, enc2),
            OpenABE_NOERROR);
  ct1.fromString("old contents");
  ASSERT_EQ(enc1->update(input1, ct1), OpenABE_NOERROR);
  ASSERT_EQ(enc2->update(input2, ct2), OpenABE_NOERROR);
  ASSERT_EQ(enc2->finalize(tag2), OpenABE_NOERROR);
  ASSERT_EQ(enc1->finalize(tag1), OpenABE_NOERROR);
  EXPECT_EQ(ct1.size(), input1.size());

  std::unique_ptr<abe_lsss::HybridDecryptStream> dec1, dec2;
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem1, iv1, dec1), OpenABE_NOERROR);
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem2, iv2, dec2), OpenABE_NOERROR);
  output.fromString("old contents");
  ASSERT_EQ(dec1->update(ct1, output), OpenABE_NOERROR);
  ASSERT_EQ(dec1->finalize(tag1), OpenABE_NOERROR);
  EXPECT_EQ(output, input1);
  ASSERT_EQ(dec2->update(ct2, output), OpenABE_NOERROR);
  ASSERT_EQ(dec2->finalize(tag2), OpenABE_NOERROR);
  EXPECT_EQ(output, input2);

  dec1.reset();
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem1, iv1, dec1), OpenABE_NOERROR);
  ASSERT_EQ(dec1->update(ct1, output), OpenABE_NOERROR);
  EXPECT_EQ(dec1->finalize(tag2), OpenABE_ERROR_DECRYPTION_FAILED);

  dec1.reset();
  ASSERT_EQ(context->decryptInit("mpk", "alice", kem1, iv2, dec1), OpenABE_NOERROR);
  ASSERT_EQ(dec1->update(ct1, output), OpenABE_NOERROR);
  EXPECT_EQ(dec1->finalize(tag1), OpenABE_ERROR_DECRYPTION_FAILED);
}

TEST_P(HybridTest, FailedInitializationDoesNotCreateStream) {
  abe_lsss::Ciphertext kem;
  abe_lsss::ByteString iv;
  iv.fromString("previous IV");
  std::unique_ptr<abe_lsss::HybridEncryptStream> enc;
  EXPECT_NE(context->encryptInit("missing", encryptionInput(), kem, iv, enc),
            OpenABE_NOERROR);
  EXPECT_FALSE(enc);
  EXPECT_TRUE(iv.empty());

  iv.fromString("previous IV");
  EXPECT_NE(context->encryptInit("mpk", nullptr, kem, iv, enc), OpenABE_NOERROR);
  EXPECT_FALSE(enc);
  EXPECT_TRUE(iv.empty());

  ASSERT_EQ(context->encryptInit("mpk", encryptionInput(), kem, iv, enc),
            OpenABE_NOERROR);
  std::unique_ptr<abe_lsss::HybridDecryptStream> dec;
  EXPECT_NE(context->decryptInit("mpk", "missing", kem, iv, dec), OpenABE_NOERROR);
  EXPECT_FALSE(dec);
  abe_lsss::ByteString badIV = iv;
  badIV.pop_back();
  EXPECT_EQ(context->decryptInit("mpk", "alice", kem, badIV, dec),
            OpenABE_ERROR_INVALID_CIPHERTEXT);
  EXPECT_FALSE(dec);
}

TEST_P(HybridTest, StreamRejectsWrongTagsAndReleasesState) {
  abe_lsss::Ciphertext kem;
  abe_lsss::ByteString iv, tag, input, ciphertext, output;
  input.fromString("message");
  std::unique_ptr<abe_lsss::HybridEncryptStream> enc;
  ASSERT_EQ(context->encryptInit("mpk", encryptionInput(), kem, iv, enc),
            OpenABE_NOERROR);
  ASSERT_EQ(enc->update(input, ciphertext), OpenABE_NOERROR);
  ASSERT_EQ(enc->finalize(tag), OpenABE_NOERROR);

  for (std::size_t length : {0u, 1u, 15u, 17u, 32u}) {
    SCOPED_TRACE(length);
    std::unique_ptr<abe_lsss::HybridDecryptStream> dec;
    ASSERT_EQ(context->decryptInit("mpk", "alice", kem, iv, dec), OpenABE_NOERROR);
    ASSERT_EQ(dec->update(ciphertext, output), OpenABE_NOERROR);
    abe_lsss::ByteString invalidTag;
    invalidTag.assign(length, 0);
    EXPECT_EQ(dec->finalize(invalidTag), OpenABE_ERROR_INVALID_TAG_LENGTH);
    EXPECT_EQ(dec->finalize(tag), OpenABE_ERROR_INVALID_CONTEXT);
  }
}

INSTANTIATE_TEST_SUITE_P(Schemes, HybridTest,
                         ::testing::Values(abe_lsss::cp_waters,
                                           abe_lsss::kp_gpsw));

}  // namespace

int main(int argc, char** argv) {
  abe_lsss::initialize();
  ::testing::InitGoogleTest(&argc, argv);
  const int result = RUN_ALL_TESTS();
  abe_lsss::shutdown();
  return result;
}
