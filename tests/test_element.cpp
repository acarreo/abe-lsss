#include <gtest/gtest.h>

#include <abe_lsss.h>

using namespace std;

namespace {

ZP withOrder(uint32_t v, const BPGroup &g) {
  ZP z(v);
  z.setOrder(g.order);
  return z;
}

OpenABEByteString zpBlob(const ZP &z) {
  OpenABEByteString blob;
  z.serialize(blob);
  return blob;
}

}  // namespace

// ZP without an order behaves as a plain integer.

TEST(ZPArithmetic, UnorderedOperandsUseIntegerArithmetic) {
  ZP x(5u), y(7u);

  ZP sum = x + y;
  EXPECT_TRUE(sum == ZP(12u));
  EXPECT_FALSE(sum.isOrderSet);

  ZP diff = x - y;
  EXPECT_TRUE(diff == -ZP(2u));
  EXPECT_FALSE(diff.isOrderSet);

  EXPECT_TRUE(x * y == ZP(35u));
  EXPECT_TRUE(-x + x == ZP(0u));
  EXPECT_TRUE(power(x, 3) == ZP(125u));
  EXPECT_TRUE(power(x, 0) == ZP(1u));
}

TEST(ZPArithmetic, OrderIsInheritedFromEitherOperand) {
  BPGroup g;
  ZP q = g.getGroupOrder();
  ZP a = withOrder(5, g);
  ZP b(7u);

  ZP left = a - b, right = b - a;
  EXPECT_TRUE(left.isOrderSet);
  EXPECT_TRUE(right.isOrderSet);
  EXPECT_TRUE(left == q - ZP(2u));
  EXPECT_TRUE(right == ZP(2u));

  ZP wrap = withOrder(1, g) + (q - ZP(1u));
  EXPECT_TRUE(wrap == ZP(0u));
  EXPECT_TRUE(wrap.isOrderSet);
}

TEST(ZPArithmetic, OrderedNegationAndMultiplicationAreReduced) {
  BPGroup g;
  ZP q = g.getGroupOrder();
  ZP three = withOrder(3, g);

  EXPECT_TRUE(-three == q - ZP(3u));
  EXPECT_TRUE(three * (q - ZP(1u)) == q - ZP(3u));
  EXPECT_TRUE(power(three, 4) == ZP(81u));
}

TEST(ZPArithmetic, DivisionRequiresAnOrder) {
  BPGroup g;
  ZP ten = withOrder(10, g), two = withOrder(2, g);

  EXPECT_TRUE(ten / two == ZP(5u));
  EXPECT_TRUE((ten / two) * two == ten);
  EXPECT_THROW(ZP(10u) / ZP(2u), OpenABE_ERROR);
  EXPECT_THROW(ten / ZP(0u), OpenABE_ERROR);

  // a divisor congruent to zero modulo the order is also zero
  ZP q = g.getGroupOrder();
  EXPECT_THROW(ten / q, OpenABE_ERROR);
}

TEST(ZPArithmetic, PowerWithZPExponent) {
  BPGroup g;
  ZP two = withOrder(2, g);

  EXPECT_TRUE(power(two, ZP(10u)) == ZP(1024u));
  EXPECT_THROW(power(ZP(2u), ZP(10u)), OpenABE_ERROR);
}

TEST(ZPArithmetic, MultInverseRequiresAnOrder) {
  BPGroup g;
  ZP three = withOrder(3, g);
  ZP inv = three;
  inv.multInverse();
  EXPECT_TRUE(inv * three == ZP(1u));

  ZP plain(3u);
  EXPECT_THROW(plain.multInverse(), OpenABE_ERROR);
}

TEST(ZPRandom, SamplesBelowTheOrderAndSetsIt) {
  BPGroup g;
  ZP q = g.getGroupOrder();

  ZP a, b;
  a.setRandom(q);
  b.setRandom(q);
  EXPECT_TRUE(a.isOrderSet);
  EXPECT_TRUE(a > ZP(0u));
  EXPECT_TRUE(a < q);
  EXPECT_TRUE(a != b);

  ZP c;
  c.setRandom(g.order);
  EXPECT_TRUE(c > ZP(0u));
  EXPECT_TRUE(c < q);
}

TEST(ZPRandom, RejectsZeroModulus) {
  ZP z, zero(0u);
  EXPECT_THROW(z.setRandom(zero), OpenABE_ERROR);
}

TEST(ZPSerialization, RoundTripsIncludingZero) {
  BPGroup g;
  for (uint32_t v : {0u, 1u, 255u, 256u, 65537u}) {
    ZP in = withOrder(v, g);
    OpenABEByteString blob = zpBlob(in);

    ZP out = withOrder(9, g);
    out.deserialize(blob);
    EXPECT_TRUE(in == out) << v;
  }

  ZP r;
  r.setRandom(g.order);
  ZP out = withOrder(9, g);
  OpenABEByteString blob = zpBlob(r);
  out.deserialize(blob);
  EXPECT_TRUE(r == out);
}

TEST(ZPSerialization, RejectsMalformedInput) {
  BPGroup g;
  OpenABEByteString good = zpBlob(withOrder(123456, g));
  ZP out = withOrder(1, g);

  OpenABEByteString empty;
  EXPECT_THROW(out.deserialize(empty), OpenABE_ERROR);

  OpenABEByteString truncated = good.getSubset(0, good.size() - 1);
  EXPECT_THROW(out.deserialize(truncated), OpenABE_ERROR);

  OpenABEByteString trailing = good;
  trailing.push_back(0);
  EXPECT_THROW(out.deserialize(trailing), OpenABE_ERROR);

  // header announces far more bytes than the buffer holds
  OpenABEByteString lying;
  for (int b : {(int)OpenABE_ELEMENT_ZP, 0xFF, 0xFF, 1, 2, 3, 4}) lying.push_back((uint8_t)b);
  EXPECT_THROW(out.deserialize(lying), OpenABE_ERROR);

  OpenABEByteString wrongType = good;
  wrongType[0] = OpenABE_ELEMENT_G1;
  EXPECT_THROW(out.deserialize(wrongType), OpenABE_ERROR);

  // a rejected blob leaves the target untouched
  EXPECT_TRUE(out == ZP(1u));
}

TEST(ZPSerialization, ValueEqualToTheOrderIsReduced) {
  BPGroup g;
  ZP q = g.getGroupOrder();
  OpenABEByteString blob = zpBlob(q);

  ZP out = withOrder(1, g);
  out.deserialize(blob);
  EXPECT_TRUE(out == ZP(0u));
}

TEST(GroupArithmetic, G1AndG2SubtractionIsAMinusB) {
  G1 a, b;
  a.setRandom();
  b.setRandom();
  EXPECT_TRUE((a + b) - b == a);
  EXPECT_TRUE(a - a == G1());
  EXPECT_FALSE(a - b == G1() - b);

  G2 c, d;
  c.setRandom();
  d.setRandom();
  EXPECT_TRUE((c + d) - d == c);
  EXPECT_TRUE(c - c == G2());
  EXPECT_FALSE(c - d == G2() - d);
}

int main(int argc, char **argv) {
  abe_lsss::initialize();
  ::testing::InitGoogleTest(&argc, argv);
  const int result = RUN_ALL_TESTS();
  abe_lsss::shutdown();
  return result;
}
