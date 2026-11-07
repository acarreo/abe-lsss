#include <abe_lsss/abe.h>
#include <abe_lsss.h>

#include <cstdint>
#include <limits>
#include <memory>

#include <openssl/evp.h>

namespace {

constexpr std::size_t kIvSize = 12;
constexpr std::size_t kTagSize = 16;
constexpr std::uint64_t kMaxPayload = (std::uint64_t{1} << 36) - 32;
constexpr char kIvComponent[] = "_GCM_IV";
constexpr char kTagComponent[] = "_GCM_TAG";
constexpr char kPayloadComponent[] = "_GCM_CT";

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

struct StreamState {
  CipherContext ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
  std::uint64_t total = 0;
};

OpenABE_ERROR update(StreamState& state, bool encrypt,
                     const OpenABEByteString& input, OpenABEByteString& output) {
  if (&input == &output) {
    return OpenABE_ERROR_INVALID_INPUT;
  }
  output.zeroize();
  if (!state.ctx) {
    return OpenABE_ERROR_INVALID_CONTEXT;
  }
  if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      input.size() > kMaxPayload - state.total) {
    return OpenABE_ERROR_INVALID_LENGTH;
  }
  if (input.empty()) {
    return OpenABE_NOERROR;
  }
  OpenABEByteString result;
  result.resize(input.size() + EVP_MAX_BLOCK_LENGTH);
  int length = 0;
  const int ok = encrypt
      ? EVP_EncryptUpdate(state.ctx.get(), result.data(), &length, input.data(),
                          static_cast<int>(input.size()))
      : EVP_DecryptUpdate(state.ctx.get(), result.data(), &length, input.data(),
                          static_cast<int>(input.size()));
  if (ok != 1) {
    result.zeroize();
    state.ctx.reset();
    return encrypt ? OpenABE_ERROR_ENCRYPTION_ERROR : OpenABE_ERROR_DECRYPTION_FAILED;
  }
  result.resize(static_cast<std::size_t>(length));
  output.swap(result);
  state.total += input.size();
  return OpenABE_NOERROR;
}

bool initialize(StreamState& state, bool encrypt, const OpenABEByteString& key,
                const OpenABEByteString& iv, const OpenABEByteString& aad) {
  if (encrypt) {
    int length = 0;
    return EVP_EncryptInit_ex(state.ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
           EVP_CIPHER_CTX_ctrl(state.ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
           EVP_EncryptInit_ex(state.ctx.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
           EVP_EncryptUpdate(state.ctx.get(), nullptr, &length, aad.data(), aad.size()) == 1;
  }
  int length = 0;
  return EVP_DecryptInit_ex(state.ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
         EVP_CIPHER_CTX_ctrl(state.ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
         EVP_DecryptInit_ex(state.ctx.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
         EVP_DecryptUpdate(state.ctx.get(), nullptr, &length, aad.data(), aad.size()) == 1;
}

}  // namespace

struct OpenABEHybridEncryptStream::Impl : StreamState {};
struct OpenABEHybridDecryptStream::Impl : StreamState {};

OpenABEHybridEncryptStream::OpenABEHybridEncryptStream(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
OpenABEHybridEncryptStream::~OpenABEHybridEncryptStream() = default;
OpenABEHybridDecryptStream::OpenABEHybridDecryptStream(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
OpenABEHybridDecryptStream::~OpenABEHybridDecryptStream() = default;

OpenABE_ERROR OpenABEHybridEncryptStream::update(const OpenABEByteString& plaintext,
                                                  OpenABEByteString& ciphertext) {
  return ::update(*impl_, true, plaintext, ciphertext);
}

OpenABE_ERROR OpenABEHybridEncryptStream::finalize(OpenABEByteString& tag) {
  tag.clear();
  if (!impl_->ctx) {
    return OpenABE_ERROR_INVALID_CONTEXT;
  }
  unsigned char finalBlock[EVP_MAX_BLOCK_LENGTH] = {};
  int length = 0;
  tag.resize(kTagSize);
  const bool ok = EVP_EncryptFinal_ex(impl_->ctx.get(), finalBlock, &length) == 1 &&
                  length == 0 &&
                  EVP_CIPHER_CTX_ctrl(impl_->ctx.get(), EVP_CTRL_GCM_GET_TAG,
                                      tag.size(), tag.data()) == 1;
  impl_->ctx.reset();
  if (!ok) {
    tag.clear();
    return OpenABE_ERROR_ENCRYPTION_ERROR;
  }
  return OpenABE_NOERROR;
}

OpenABE_ERROR OpenABEHybridDecryptStream::update(const OpenABEByteString& ciphertext,
                                                  OpenABEByteString& plaintext) {
  return ::update(*impl_, false, ciphertext, plaintext);
}

OpenABE_ERROR OpenABEHybridDecryptStream::finalize(const OpenABEByteString& tag) {
  if (!impl_->ctx) {
    return OpenABE_ERROR_INVALID_CONTEXT;
  }
  if (tag.size() != kTagSize) {
    impl_->ctx.reset();
    return OpenABE_ERROR_INVALID_TAG_LENGTH;
  }
  OpenABEByteString mutableTag = tag;
  unsigned char finalBlock[EVP_MAX_BLOCK_LENGTH] = {};
  int length = 0;
  const bool ok = EVP_CIPHER_CTX_ctrl(impl_->ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                      mutableTag.size(), mutableTag.data()) == 1 &&
                  EVP_DecryptFinal_ex(impl_->ctx.get(), finalBlock, &length) == 1 &&
                  length == 0;
  impl_->ctx.reset();
  return ok ? OpenABE_NOERROR : OpenABE_ERROR_DECRYPTION_FAILED;
}

OpenABEContextSchemeHybrid::OpenABEContextSchemeHybrid(
    std::unique_ptr<OpenABEContextABE> kem)
    : OpenABEContextSchemeCPA(std::move(kem)) {}

OpenABE_ERROR OpenABEContextSchemeHybrid::encryptInit(
    const std::string& mpkID, const OpenABEFunctionInput* encryptInput,
    OpenABECiphertext& ciphertext, OpenABEByteString& iv,
    std::unique_ptr<OpenABEHybridEncryptStream>& stream) {
  if (stream) {
    return OpenABE_ERROR_IN_USE_ALREADY;
  }
  iv.clear();
  if (ciphertext.getUID().size() != UID_LEN) {
    return OpenABE_ERROR_INVALID_CIPHERTEXT_HEADER;
  }
  try {
    for (const auto& name : ciphertext.getKeys()) {
      ciphertext.deleteComponent(name);
    }
    auto key = std::make_shared<OpenABESymKey>();
    OpenABE_ERROR result = m_KEM_->encryptKEM(mpkID, encryptInput,
                                              DEFAULT_SYM_KEY_BYTES, key,
                                              ciphertext);
    if (result != OpenABE_NOERROR) return result;
    if (key->getKeyBytes().size() != DEFAULT_SYM_KEY_BYTES) return OpenABE_ERROR_INVALID_KEY;
    OpenABEByteString aad;
    ciphertext.getHeader(aad);
    auto impl = std::make_unique<OpenABEHybridEncryptStream::Impl>();
    if (!impl->ctx) return OpenABE_ERROR_OUT_OF_MEMORY;
    getRandomBytes(iv, kIvSize);
    if (!initialize(*impl, true, key->getKeyBytes(), iv, aad)) {
      iv.clear();
      return OpenABE_ERROR_ENCRYPTION_ERROR;
    }
    stream.reset(new OpenABEHybridEncryptStream(std::move(impl)));
    return OpenABE_NOERROR;
  } catch (OpenABE_ERROR error) {
    iv.clear();
    return error;
  }
}

OpenABE_ERROR OpenABEContextSchemeHybrid::decryptInit(
    const std::string& mpkID, const std::string& keyID,
    OpenABECiphertext& ciphertext, const OpenABEByteString& iv,
    std::unique_ptr<OpenABEHybridDecryptStream>& stream) {
  if (stream) {
    return OpenABE_ERROR_IN_USE_ALREADY;
  }
  if (ciphertext.getSchemeType() != m_KEM_->getSchemeType() ||
      ciphertext.getUID().size() != UID_LEN) {
    return OpenABE_ERROR_INVALID_CIPHERTEXT_HEADER;
  }
  if (iv.size() != kIvSize) {
    return OpenABE_ERROR_INVALID_CIPHERTEXT;
  }
  try {
    auto key = std::make_shared<OpenABESymKey>();
    OpenABE_ERROR result = m_KEM_->decryptKEM(mpkID, keyID, ciphertext,
                                              DEFAULT_SYM_KEY_BYTES, key);
    if (result != OpenABE_NOERROR) return result;
    if (key->getKeyBytes().size() != DEFAULT_SYM_KEY_BYTES) return OpenABE_ERROR_INVALID_KEY;
    OpenABEByteString aad;
    ciphertext.getHeader(aad);
    auto impl = std::make_unique<OpenABEHybridDecryptStream::Impl>();
    if (!impl->ctx) return OpenABE_ERROR_OUT_OF_MEMORY;
    if (!initialize(*impl, false, key->getKeyBytes(), iv, aad)) {
      return OpenABE_ERROR_DECRYPTION_FAILED;
    }
    stream.reset(new OpenABEHybridDecryptStream(std::move(impl)));
    return OpenABE_NOERROR;
  } catch (OpenABE_ERROR error) {
    return error;
  }
}

OpenABE_ERROR OpenABEContextSchemeHybrid::encrypt(
    const std::string& mpkID, const OpenABEFunctionInput* encryptInput,
    OpenABEByteString& plaintext, OpenABECiphertext& ciphertext) {
  if (plaintext.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return OpenABE_ERROR_INVALID_LENGTH;
  }
  OpenABEByteString iv, payload, tag;
  std::unique_ptr<OpenABEHybridEncryptStream> stream;
  OpenABE_ERROR result = encryptInit(mpkID, encryptInput, ciphertext, iv, stream);
  if (result != OpenABE_NOERROR) return result;
  result = stream->update(plaintext, payload);
  if (result != OpenABE_NOERROR) return result;
  result = stream->finalize(tag);
  if (result != OpenABE_NOERROR) return result;
  ciphertext.setComponent(kIvComponent, &iv);
  ciphertext.setComponent(kPayloadComponent, &payload);
  ciphertext.setComponent(kTagComponent, &tag);
  return OpenABE_NOERROR;
}

OpenABE_ERROR OpenABEContextSchemeHybrid::decrypt(
    const std::string& mpkID, const std::string& keyID,
    OpenABEByteString& plaintext, OpenABECiphertext& ciphertext) {
  plaintext.zeroize();
  try {
    if (ciphertext.getSchemeType() != m_KEM_->getSchemeType() ||
        ciphertext.getUID().size() != UID_LEN) {
      return OpenABE_ERROR_INVALID_CIPHERTEXT_HEADER;
    }
    auto* iv = ciphertext.getByteString(kIvComponent);
    auto* payload = ciphertext.getByteString(kPayloadComponent);
    auto* tag = ciphertext.getByteString(kTagComponent);
    if (!iv || !payload || !tag || iv->size() != kIvSize ||
        tag->size() != kTagSize ||
        payload->size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
      return OpenABE_ERROR_INVALID_CIPHERTEXT;
    }
    std::unique_ptr<OpenABEHybridDecryptStream> stream;
    OpenABE_ERROR result = decryptInit(mpkID, keyID, ciphertext, *iv, stream);
    if (result != OpenABE_NOERROR) return result;
    OpenABEByteString candidate;
    result = stream->update(*payload, candidate);
    if (result == OpenABE_NOERROR) result = stream->finalize(*tag);
    if (result == OpenABE_NOERROR) plaintext.swap(candidate);
    candidate.zeroize();
    return result;
  } catch (OpenABE_ERROR error) {
    return error;
  }
}
