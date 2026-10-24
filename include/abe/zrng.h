#ifndef __ZRNG_H__
#define __ZRNG_H__

#include <array>
#include <cstddef>
#include <cstdint>

#include "zabe.h"

/// \class  OpenABERNG
/// \brief  Source of random bytes. Implementations either draw from the
///         system (OpenABESystemRNG) or expand a seed deterministically
///         (OpenABEShakeRNG).
class OpenABERNG {
public:
  virtual ~OpenABERNG() = default;

  /// Fill buf with len bytes.
  virtual void getRandomBytes(uint8_t *buf, size_t len) = 0;
  /// Replace the content of buf with len bytes.
  void getRandomBytes(OpenABEByteString &buf, size_t len);
};

/// \class  OpenABESystemRNG
/// \brief  Non-deterministic generator backed by the RELIC random source.
class OpenABESystemRNG : public OpenABERNG {
public:
  void getRandomBytes(uint8_t *buf, size_t len) override;
  using OpenABERNG::getRandomBytes;
};

/// \class  OpenABEShakeRNG
/// \brief  Deterministic generator: the output stream is a function of
///         (seed, personalization) only. It is built on SHAKE256 in counter
///         mode, block_i = SHAKE256(domain || |seed| || seed ||
///         |personalization| || personalization || i), and does not depend
///         on how requests are split: n1 bytes followed by n2 bytes equal
///         n1 + n2 bytes.
///
///         Not meant for key generation: use it only where reproducibility
///         is required (e.g. re-derivation of randomness from a secret seed).
class OpenABEShakeRNG : public OpenABERNG {
public:
  static constexpr size_t BLOCK_BYTES = 4096;

  explicit OpenABEShakeRNG(const OpenABEByteString &seed,
                           const OpenABEByteString &personalization = OpenABEByteString());
  ~OpenABEShakeRNG() override;
  OpenABEShakeRNG(const OpenABEShakeRNG &) = delete;
  OpenABEShakeRNG &operator=(const OpenABEShakeRNG &) = delete;

  void getRandomBytes(uint8_t *buf, size_t len) override;
  using OpenABERNG::getRandomBytes;

private:
  void refill();

  OpenABEByteString input_prefix_;
  uint64_t counter_;
  std::array<uint8_t, BLOCK_BYTES> block_;
  size_t offset_;
};

#endif /* __ZRNG_H__ */
