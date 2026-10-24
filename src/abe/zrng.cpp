#include <cstring>
#include <memory>

#include <openssl/evp.h>

#include <abe_lsss.h>

#include "abe/zrng.h"

using namespace std;

void getRandomBytes(uint8_t *buf, size_t buf_len);

namespace {

const char kDomain[] = "abe-lsss/shake-rng/v1";

void appendBE64(OpenABEByteString &out, uint64_t v) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<uint8_t>(v >> shift));
  }
}

struct MdCtxDeleter {
  void operator()(EVP_MD_CTX *ctx) const { EVP_MD_CTX_free(ctx); }
};

}  // namespace

void OpenABERNG::getRandomBytes(OpenABEByteString &buf, size_t len) {
  buf.clear();
  buf.fillBuffer(0, len);
  if (len > 0) {
    this->getRandomBytes(buf.getInternalPtr(), len);
  }
}

void OpenABESystemRNG::getRandomBytes(uint8_t *buf, size_t len) {
  if (len > 0) {
    ASSERT_NOTNULL(buf);
    ::getRandomBytes(buf, len);
  }
}

OpenABEShakeRNG::OpenABEShakeRNG(const OpenABEByteString &seed,
                                 const OpenABEByteString &personalization)
    : counter_(0), offset_(BLOCK_BYTES) {
  input_prefix_.insert(input_prefix_.end(), kDomain,
                       kDomain + sizeof(kDomain) - 1);
  appendBE64(input_prefix_, seed.size());
  input_prefix_ += seed;
  appendBE64(input_prefix_, personalization.size());
  input_prefix_ += personalization;
  block_.fill(0);
}

OpenABEShakeRNG::~OpenABEShakeRNG() {
  input_prefix_.zeroize();
  OpenABEZeroize(block_.data(), block_.size());
}

void OpenABEShakeRNG::refill() {
  OpenABEByteString input = input_prefix_;
  appendBE64(input, counter_++);

  unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_shake256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1 ||
      EVP_DigestFinalXOF(ctx.get(), block_.data(), block_.size()) != 1) {
    input.zeroize();
    throw OpenABE_ERROR_UNKNOWN;
  }
  input.zeroize();
  offset_ = 0;
}

void OpenABEShakeRNG::getRandomBytes(uint8_t *buf, size_t len) {
  if (len == 0) {
    return;
  }
  ASSERT_NOTNULL(buf);
  while (len > 0) {
    if (offset_ == BLOCK_BYTES) {
      refill();
    }
    const size_t n = min(len, BLOCK_BYTES - offset_);
    memcpy(buf, block_.data() + offset_, n);
    offset_ += n;
    buf += n;
    len -= n;
  }
}
