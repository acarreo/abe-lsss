#include <gtest/gtest.h>

#include <abe_lsss.h>

using namespace std;

namespace {

OpenABEByteString bytes(const string &s) {
  OpenABEByteString b;
  b.insert(b.end(), s.begin(), s.end());
  return b;
}


}  // namespace

TEST(Container, EmptyContainersAreEqual) {
  OpenABEContainer a, b;
  EXPECT_TRUE(a == b);
}

TEST(Container, EqualWhenSameKeysAndValues) {
  OpenABEContainer a, b;
  OpenABEByteString p = bytes("policy"), q = bytes("policy");
  G1 g;
  g.setRandom();
  a.setComponent("policy", &p);
  a.setComponent("C", &g);
  OpenABEUInteger seven(7);
  a.setComponent("n", &seven);
  b.setComponent("n", &seven);
  b.setComponent("C", &g);
  b.setComponent("policy", &q);
  EXPECT_TRUE(a == b);
  EXPECT_TRUE(b == a);
}

TEST(Container, ByteStringValuesAreCompared) {
  OpenABEContainer a, b;
  OpenABEByteString p = bytes("abc"), q = bytes("abd"), r = bytes("abcd");
  a.setComponent("x", &p);
  b.setComponent("x", &q);
  EXPECT_FALSE(a == b);
  OpenABEContainer c;
  c.setComponent("x", &r);
  EXPECT_FALSE(a == c);
}

TEST(Container, DifferentKeySetsAreDifferentInBothDirections) {
  OpenABEContainer a, b, c;
  OpenABEByteString p = bytes("v");
  a.setComponent("x", &p);
  b.setComponent("x", &p);
  b.setComponent("y", &p);
  c.setComponent("z", &p);
  EXPECT_FALSE(a == b);
  EXPECT_FALSE(b == a);
  EXPECT_FALSE(a == c);
  EXPECT_FALSE(c == a);
}

TEST(Container, DifferentTypesUnderSameKeyAreDifferent) {
  OpenABEContainer a, b;
  OpenABEByteString p = bytes("v");
  a.setComponent("x", &p);
  OpenABEUInteger one(1);
  b.setComponent("x", &one);
  EXPECT_FALSE(a == b);
  EXPECT_FALSE(b == a);
}

TEST(Container, GroupElementsAreCompared) {
  OpenABEContainer a, b;
  G1 g1, g2;
  g1.setRandom();
  g2.setRandom();
  a.setComponent("C", &g1);
  b.setComponent("C", &g2);
  EXPECT_FALSE(a == b);
  b.setComponent("C", &g1);
  EXPECT_TRUE(a == b);
}

TEST(Container, ComparisonDoesNotInsertMissingKeys) {
  OpenABEContainer a, b;
  OpenABEByteString p = bytes("v");
  a.setComponent("x", &p);
  EXPECT_FALSE(a == b);
  EXPECT_EQ(a.numComponents(), 1u);
  EXPECT_EQ(b.numComponents(), 0u);
}

TEST(Ciphertext, HeaderIsPartOfEquality) {
  OpenABEByteString uid1 = bytes("0123456789abcdef0123456789abcdef");
  OpenABEByteString uid2 = bytes("fedcba9876543210fedcba9876543210");
  OpenABECiphertext a(uid1), b(uid1), c(uid2);
  OpenABEByteString p = bytes("payload");
  for (OpenABECiphertext *ct : {&a, &b, &c}) {
    ct->setComponent("_ED", &p);
    ct->setSchemeType(OpenABE_SCHEME_CP_WATERS);
  }
  EXPECT_TRUE(a == b);
  EXPECT_FALSE(a == c);

  b.setSchemeType(OpenABE_SCHEME_KP_GPSW);
  EXPECT_FALSE(a == b);
}

TEST(Ciphertext, ComponentsArePartOfEquality) {
  OpenABEByteString uid = bytes("0123456789abcdef0123456789abcdef");
  OpenABECiphertext a(uid), b(uid);
  OpenABEByteString p = bytes("payload"), q = bytes("Payload");
  a.setComponent("_ED", &p);
  b.setComponent("_ED", &q);
  EXPECT_FALSE(a == b);
  b.setComponent("_ED", &p);
  EXPECT_TRUE(a == b);
}

TEST(AttributeList, SerializeRoundTrip) {
  auto a = createAttributeList("Alice|Bob|Org:Carol");
  ASSERT_TRUE(a != nullptr);
  OpenABEByteString blob;
  a->serialize(blob);
  OpenABEAttributeList b;
  b.deserialize(blob);
  EXPECT_TRUE(a->isEqual(&b));
  EXPECT_TRUE(b.isEqual(a.get()));
  EXPECT_EQ(b.getAttributeList()->size(), 3u);

  OpenABEAttributeList empty;
  EXPECT_FALSE(a->isEqual(&empty));
  EXPECT_FALSE(empty.isEqual(a.get()));
}

TEST(AttributeList, EqualityIgnoresOrderAndDetectsDifferences) {
  auto a = createAttributeList("A|B|C");
  auto b = createAttributeList("C|A|B");
  auto c = createAttributeList("A|B");
  auto d = createAttributeList("A|B|D");
  ASSERT_TRUE(a && b && c && d);
  EXPECT_TRUE(a->isEqual(b.get()));
  EXPECT_FALSE(a->isEqual(c.get()));
  EXPECT_FALSE(c->isEqual(a.get()));
  EXPECT_FALSE(a->isEqual(d.get()));
}

int main(int argc, char **argv) {
  abe_lsss::initialize();
  ::testing::InitGoogleTest(&argc, argv);
  const int result = RUN_ALL_TESTS();
  abe_lsss::shutdown();
  return result;
}
