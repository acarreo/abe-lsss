#include <gtest/gtest.h>

#include <abe_lsss.h>

#include <set>
#include <string>

using namespace std;

namespace {

OpenABEByteString fromAscii(const string &s) {
  OpenABEByteString b;
  b.insert(b.end(), s.begin(), s.end());
  return b;
}

string hexOf(OpenABERNG &rng, size_t offset, size_t len) {
  OpenABEByteString all;
  rng.getRandomBytes(all, offset + len);
  return all.getSubset(offset, len).toLowerHex();
}

// Reference values computed independently with Python's hashlib.shake_256:
//   block_i = shake_256(domain || be64(|seed|) || seed ||
//                       be64(|pers|) || pers || be64(i)).digest(4096)
const char *kSeed = "abe-lsss test seed";

}  // namespace

TEST(ShakeRNG, MatchesKnownAnswerVectors) {
  OpenABEShakeRNG rng(fromAscii(kSeed));
  EXPECT_EQ(hexOf(rng, 0, 32),
            "e862e3bcb58d4454dec53da5d9c2709fc4f2eb5fbfb35b4eacc03e5927ac4401");

  // Spans the first block boundary (4096 bytes).
  OpenABEShakeRNG rng2(fromAscii(kSeed));
  EXPECT_EQ(hexOf(rng2, 4090, 16), "8cf6ce68c414c9bdffc09f3c61beca79");

  // Spans the second block boundary.
  OpenABEShakeRNG rng3(fromAscii(kSeed));
  EXPECT_EQ(hexOf(rng3, 8190, 16), "ad1d4c552d4a71b0f313eb25681790bb");
}

TEST(ShakeRNG, PersonalizationIsPartOfTheStream) {
  OpenABEShakeRNG rng(fromAscii(kSeed), fromAscii("nonce"));
  EXPECT_EQ(hexOf(rng, 0, 32),
            "e1dac0f38812ceda0bba640c59d70fcad9a8e81f25435b28e6ebd4f37de0b03b");
}

TEST(ShakeRNG, EmptySeedIsAccepted) {
  OpenABEShakeRNG rng{OpenABEByteString()};
  EXPECT_EQ(hexOf(rng, 0, 32),
            "507f862ea13e1ad7dd50b8b6a2a626e5a85cc1183f0bcc667d6e01382bfbb194");
}

TEST(ShakeRNG, IsDeterministicAndIndependentOfRequestSplit) {
  OpenABEShakeRNG whole(fromAscii(kSeed));
  OpenABEByteString expected;
  whole.getRandomBytes(expected, 10000);

  OpenABEShakeRNG pieces(fromAscii(kSeed));
  OpenABEByteString assembled, chunk;
  for (size_t n : {1u, 7u, 4088u, 1u, 4096u, 1807u}) {
    pieces.getRandomBytes(chunk, n);
    assembled += chunk;
  }
  ASSERT_EQ(assembled.size(), expected.size());
  EXPECT_EQ(assembled, expected);
}

TEST(ShakeRNG, SeedAndPersonalizationLengthsAreDomainSeparated) {
  // "ab"+"c" and "a"+"bc" must not collide.
  OpenABEShakeRNG r1(fromAscii("ab"), fromAscii("c"));
  OpenABEShakeRNG r2(fromAscii("a"), fromAscii("bc"));
  OpenABEShakeRNG r3(fromAscii("abc"));
  const string h1 = hexOf(r1, 0, 32), h2 = hexOf(r2, 0, 32),
               h3 = hexOf(r3, 0, 32);
  EXPECT_NE(h1, h2);
  EXPECT_NE(h1, h3);
  EXPECT_NE(h2, h3);
}

TEST(ShakeRNG, ZeroLengthRequestsAreNoOps) {
  OpenABEShakeRNG a(fromAscii(kSeed)), b(fromAscii(kSeed));
  OpenABEByteString empty;
  a.getRandomBytes(empty, 0);
  EXPECT_EQ(empty.size(), 0u);
  a.getRandomBytes(nullptr, 0);
  EXPECT_EQ(hexOf(a, 0, 32), hexOf(b, 0, 32));
}

TEST(SystemRNG, ProducesDistinctNonTrivialOutput) {
  OpenABESystemRNG rng;
  set<string> seen;
  for (int i = 0; i < 8; ++i) {
    OpenABEByteString out;
    rng.getRandomBytes(out, 32);
    ASSERT_EQ(out.size(), 32u);
    EXPECT_TRUE(seen.insert(out.toLowerHex()).second);
  }
  OpenABEByteString none;
  rng.getRandomBytes(none, 0);
  EXPECT_EQ(none.size(), 0u);
}

TEST(RNGInterface, WorksThroughBasePointer) {
  OpenABEShakeRNG det(fromAscii(kSeed));
  OpenABESystemRNG sys;
  for (OpenABERNG *rng : {static_cast<OpenABERNG *>(&det),
                          static_cast<OpenABERNG *>(&sys)}) {
    uint8_t buf[17] = {0};
    rng->getRandomBytes(buf, sizeof(buf));
    bool nonZero = false;
    for (uint8_t v : buf) nonZero |= (v != 0);
    EXPECT_TRUE(nonZero);
  }
}

int main(int argc, char **argv) {
  abe_lsss::initialize();
  ::testing::InitGoogleTest(&argc, argv);
  const int result = RUN_ALL_TESTS();
  abe_lsss::shutdown();
  return result;
}
