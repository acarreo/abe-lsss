#include <benchmark/benchmark.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>

#include <abe_lsss.h>
#include <abe_lsss/abe.h>

namespace {

constexpr std::size_t kAeadChunkSize = 64 * 1024;
constexpr const char* kPolicy = "(Engineering and ProjectA)";
constexpr const char* kAttributes = "Engineering|ProjectA";

struct BenchmarkContext {
  std::unique_ptr<OpenABEContextSchemeCPA> context;
  std::unique_ptr<OpenABEFunctionInput> policy;
  std::unique_ptr<OpenABEFunctionInput> attributes;
  OpenABEByteString message;
};

static bool initializeBenchmark(benchmark::State& state,
                                BenchmarkContext& data) {
  const auto messageSize = static_cast<std::size_t>(state.range(0));
  data.context = abe_lsss::create_context(abe_lsss::cp_waters);
  data.policy = abe_lsss::parse_policy(kPolicy);
  data.attributes = abe_lsss::parse_attributes(kAttributes);
  if (!data.context || !data.policy || !data.attributes ||
      data.context->generateParams("MPK", "MSK") != OpenABE_NOERROR ||
      data.context->keygen(data.attributes.get(), "Alice", "MPK", "MSK") !=
          OpenABE_NOERROR) {
    state.SkipWithError("Could not initialize CP-ABE benchmark");
    return false;
  }

  getRandomBytes(data.message, messageSize);
  state.counters["payload_bytes"] = static_cast<double>(messageSize);
  return true;
}

static bool check(OpenABE_ERROR result, benchmark::State& state,
                 const char* operation) {
  if (result == OpenABE_NOERROR) {
    return true;
  }
  const std::string message =
      std::string(operation) + ": " + OpenABE_errorToString(result);
  state.SkipWithError(message.c_str());
  return false;
}

static bool setAad(OpenABESymKeyAuthEncStream& stream,
                   const OpenABEByteString& aad, benchmark::State& state) {
  OpenABEByteString mutableAad = aad;
  stream.initAddAuthData(mutableAad.data(),
                         static_cast<uint32_t>(mutableAad.size()));
  return check(stream.setAddAuthData(), state, "Setting AES-GCM AAD");
}

static bool encryptAead(OpenABEByteString& message,
                        const std::shared_ptr<OpenABESymKey>& key,
                        const OpenABEByteString& aad,
                        OpenABEByteString& ciphertext, OpenABEByteString& iv,
                        OpenABEByteString& tag, benchmark::State& state) {
  OpenABESymKeyAuthEncStream stream(DEFAULT_AES_SEC_LEVEL, key);
  if (!check(stream.encryptInit(iv), state, "Starting AES-GCM encryption") ||
      !setAad(stream, aad, state)) {
    return false;
  }

  ciphertext.clear();
  ciphertext.reserve(message.size());
  for (std::size_t offset = 0; offset < message.size();
       offset += kAeadChunkSize) {
    const std::size_t count =
        std::min(kAeadChunkSize, message.size() - offset);
    OpenABEByteString inputBlock = message.getSubset(offset, count);
    if (!check(stream.encryptUpdate(inputBlock, ciphertext), state,
               "Encrypting an AES-GCM block")) {
      return false;
    }
  }
  OpenABEByteString finalBlock;
  return check(stream.encryptFinalize(finalBlock, tag), state,
               "Finalizing AES-GCM encryption");
}

static bool decryptAead(OpenABEByteString& ciphertext,
                        OpenABEByteString& iv, OpenABEByteString& tag,
                        const std::shared_ptr<OpenABESymKey>& key,
                        const OpenABEByteString& aad,
                        OpenABEByteString& plaintext,
                        benchmark::State& state) {
  OpenABESymKeyAuthEncStream stream(DEFAULT_AES_SEC_LEVEL, key);
  if (!check(stream.decryptInit(iv, tag),
             state, "Starting AES-GCM decryption") ||
      !setAad(stream, aad, state)) {
    return false;
  }

  plaintext.clear();
  plaintext.reserve(ciphertext.size());
  for (std::size_t offset = 0; offset < ciphertext.size();
       offset += kAeadChunkSize) {
    const std::size_t count =
        std::min(kAeadChunkSize, ciphertext.size() - offset);
    OpenABEByteString inputBlock = ciphertext.getSubset(offset, count);
    if (!check(stream.decryptUpdate(inputBlock, plaintext), state,
               "Decrypting an AES-GCM block")) {
      return false;
    }
  }
  return check(stream.decryptFinalize(plaintext), state,
               "Verifying the AES-GCM tag");
}

static bool verifyPlaintext(const OpenABEByteString& plaintext,
                            const OpenABEByteString& expected,
                            benchmark::State& state) {
  if (plaintext.size() != expected.size() ||
      !std::equal(plaintext.begin(), plaintext.end(), expected.begin())) {
    state.SkipWithError("Decrypted payload does not match the original");
    return false;
  }
  return true;
}

static bool wrapAeadKey(BenchmarkContext& data,
                        OpenABEByteString& keyBytes,
                        OpenABECiphertext& wrappedKey,
                        benchmark::State& state) {
  auto key = std::make_shared<OpenABESymKey>();
  if (!key->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES)) {
    state.SkipWithError("Could not generate an AES-256 key");
    return false;
  }
  keyBytes = key->getKeyBytes();
  return check(data.context->encrypt("MPK", data.policy.get(), keyBytes,
                                    wrappedKey),
               state, "Encrypting the AES key with CP-ABE");
}

static bool unwrapAeadKey(BenchmarkContext& data,
                          OpenABECiphertext& wrappedKey,
                          OpenABEByteString& keyBytes,
                          benchmark::State& state) {
  return check(data.context->decrypt("MPK", "Alice", keyBytes, wrappedKey),
               state, "Decrypting the AES key with CP-ABE");
}

static std::shared_ptr<OpenABESymKey> makeAeadKey(OpenABEByteString& keyBytes) {
  auto key = std::make_shared<OpenABESymKey>();
  key->setSymmetricKey(keyBytes);
  return key;
}

static void BM_DirectABE_Encrypt(benchmark::State& state) {
  BenchmarkContext data;
  if (!initializeBenchmark(state, data)) {
    return;
  }

  OpenABECiphertext ciphertext;
  for (auto _ : state) {
    if (!check(data.context->encrypt("MPK", data.policy.get(), data.message,
                                     ciphertext),
               state, "Encrypting the message with ABE")) {
      break;
    }
    benchmark::DoNotOptimize(ciphertext);
  }
  if (!state.error_occurred()) {
    OpenABEByteString plaintext;
    if (!check(data.context->decrypt("MPK", "Alice", plaintext, ciphertext),
               state, "Verifying direct ABE encryption") ||
        !verifyPlaintext(plaintext, data.message, state)) {
      return;
    }
  }
  state.SetBytesProcessed(
      static_cast<int64_t>(data.message.size()) * state.iterations());
}

static void BM_DirectABE_Decrypt(benchmark::State& state) {
  BenchmarkContext data;
  if (!initializeBenchmark(state, data)) {
    return;
  }

  OpenABECiphertext ciphertext;
  if (!check(data.context->encrypt("MPK", data.policy.get(), data.message,
                                   ciphertext),
             state, "Preparing the ABE ciphertext")) {
    return;
  }
  OpenABEByteString plaintext;
  for (auto _ : state) {
    if (!check(data.context->decrypt("MPK", "Alice", plaintext, ciphertext),
               state, "Decrypting the message with ABE")) {
      break;
    }
    benchmark::DoNotOptimize(plaintext);
  }
  if (!state.error_occurred() &&
      !verifyPlaintext(plaintext, data.message, state)) {
    return;
  }
  state.SetBytesProcessed(
      static_cast<int64_t>(data.message.size()) * state.iterations());
}

static void BM_ABE_AESGCM_Encrypt(benchmark::State& state) {
  BenchmarkContext data;
  if (!initializeBenchmark(state, data)) {
    return;
  }

  OpenABEByteString keyBytes, ciphertextBytes, iv, tag, aad;
  OpenABECiphertext wrappedKey;
  for (auto _ : state) {
    if (!wrapAeadKey(data, keyBytes, wrappedKey, state)) {
      break;
    }
    wrappedKey.getHeader(aad);
    auto key = makeAeadKey(keyBytes);
    if (!encryptAead(data.message, key, aad, ciphertextBytes, iv, tag, state)) {
      break;
    }
    benchmark::DoNotOptimize(ciphertextBytes);
  }
  if (!state.error_occurred()) {
    OpenABEByteString recoveredKeyBytes, plaintext;
    if (!unwrapAeadKey(data, wrappedKey, recoveredKeyBytes, state) ||
        !decryptAead(ciphertextBytes, iv, tag, makeAeadKey(recoveredKeyBytes),
                     aad, plaintext, state) ||
        !verifyPlaintext(plaintext, data.message, state)) {
      return;
    }
  }
  state.SetBytesProcessed(
      static_cast<int64_t>(data.message.size()) * state.iterations());
}

static void BM_ABE_AESGCM_Decrypt(benchmark::State& state) {
  BenchmarkContext data;
  if (!initializeBenchmark(state, data)) {
    return;
  }

  OpenABEByteString keyBytes, ciphertextBytes, iv, tag, aad;
  OpenABECiphertext wrappedKey;
  if (!wrapAeadKey(data, keyBytes, wrappedKey, state)) {
    return;
  }
  wrappedKey.getHeader(aad);
  auto encryptionKey = makeAeadKey(keyBytes);
  if (!encryptAead(data.message, encryptionKey, aad, ciphertextBytes, iv, tag,
                   state)) {
    return;
  }

  OpenABEByteString serializedKey;
  wrappedKey.exportToBytes(serializedKey);
  OpenABECiphertext serializedWrappedKey;
  serializedWrappedKey.loadFromBytes(serializedKey);
  OpenABEByteString plaintext;
  for (auto _ : state) {
    OpenABEByteString recoveredKeyBytes;
    if (!unwrapAeadKey(data, serializedWrappedKey, recoveredKeyBytes, state)) {
      break;
    }
    auto decryptionKey = makeAeadKey(recoveredKeyBytes);
    if (!decryptAead(ciphertextBytes, iv, tag, decryptionKey, aad, plaintext,
                     state)) {
      break;
    }
    benchmark::DoNotOptimize(plaintext);
  }
  if (!state.error_occurred() &&
      !verifyPlaintext(plaintext, data.message, state)) {
    return;
  }
  state.SetBytesProcessed(
      static_cast<int64_t>(data.message.size()) * state.iterations());
}

static void registerPayloadSize(benchmark::Benchmark* benchmark) {
  for (int size : {32, 1024 * 1024, 16 * 1024 * 1024, 1024 * 1024 * 1024}) {
    benchmark->Args({size})->Iterations(1);
  }
}

}  // namespace

BENCHMARK(BM_DirectABE_Encrypt)->Apply(registerPayloadSize);
BENCHMARK(BM_DirectABE_Decrypt)->Apply(registerPayloadSize);
BENCHMARK(BM_ABE_AESGCM_Encrypt)->Apply(registerPayloadSize);
BENCHMARK(BM_ABE_AESGCM_Decrypt)->Apply(registerPayloadSize);

int main(int argc, char** argv) {
  abe_lsss::initialize();
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  abe_lsss::shutdown();
  return 0;
}
