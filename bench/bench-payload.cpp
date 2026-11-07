#include <benchmark/benchmark.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <abe_lsss.h>
#include <abe_lsss/abe.h>

namespace {

constexpr std::size_t kAEADChunkSize = 64 * 1024;
constexpr const char* kPolicy = "(Engineering and ProjectA)";
constexpr const char* kAttributes = "Engineering|ProjectA";

template <typename Context>
struct PayloadBenchmarkContext {
  std::unique_ptr<Context> context;
  std::unique_ptr<abe_lsss::FunctionInput> policy;
  std::unique_ptr<abe_lsss::FunctionInput> attributes;
  abe_lsss::ByteString message;
};

using BenchmarkContext = PayloadBenchmarkContext<abe_lsss::CPAContext>;
using HybridBenchmarkContext = PayloadBenchmarkContext<abe_lsss::HybridContext>;

template <typename Context>
static bool initializeBenchmark(benchmark::State& state,
                                PayloadBenchmarkContext<Context>& data,
                                std::unique_ptr<Context> context,
                                abe_lsss::Scheme scheme) {
  const auto messageSize = static_cast<std::size_t>(state.range(0));
  data.context = std::move(context);
  data.policy = abe_lsss::parse_policy(kPolicy);
  data.attributes = abe_lsss::parse_attributes(kAttributes);
  auto* keyInput = scheme == abe_lsss::cp_waters ? data.attributes.get()
                                                  : data.policy.get();
  if (!data.context || !data.policy || !data.attributes ||
      data.context->generateParams("MPK", "MSK") != OpenABE_NOERROR ||
      data.context->keygen(keyInput, "Alice", "MPK", "MSK") !=
          OpenABE_NOERROR) {
    state.SkipWithError("Could not initialize ABE benchmark");
    return false;
  }

  getRandomBytes(data.message, messageSize);
  state.counters["payload_bytes"] = static_cast<double>(messageSize);
  return true;
}

static bool initializeBenchmark(benchmark::State& state, BenchmarkContext& data) {
  return initializeBenchmark(state, data, abe_lsss::create_context(abe_lsss::cp_waters),
                             abe_lsss::cp_waters);
}

static bool initializeBenchmark(benchmark::State& state,
                                HybridBenchmarkContext& data,
                                abe_lsss::Scheme scheme) {
  return initializeBenchmark(state, data, abe_lsss::create_hybrid_context(scheme),
                             scheme);
}

static const abe_lsss::FunctionInput* encryptionInput(
    const HybridBenchmarkContext& data, abe_lsss::Scheme scheme) {
  return scheme == abe_lsss::cp_waters ? data.policy.get() : data.attributes.get();
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

static bool setAAD(abe_lsss::AES_GCM_Stream& stream,
                   const abe_lsss::ByteString& aad, benchmark::State& state) {
  abe_lsss::ByteString mutableAAD = aad;
  stream.initAddAuthData(mutableAAD.data(),
                         static_cast<uint32_t>(mutableAAD.size()));
  return check(stream.setAddAuthData(), state, "Setting AES-GCM AAD");
}

static bool encryptAEAD(abe_lsss::ByteString& message,
                        const std::shared_ptr<abe_lsss::SymmetricKey>& key,
                        const abe_lsss::ByteString& aad,
                        abe_lsss::ByteString& ciphertext, abe_lsss::ByteString& iv,
                        abe_lsss::ByteString& tag, benchmark::State& state) {
  abe_lsss::AES_GCM_Stream stream(DEFAULT_AES_SEC_LEVEL, key);
  if (!check(stream.encryptInit(iv), state, "Starting AES-GCM encryption") ||
      !setAAD(stream, aad, state)) {
    return false;
  }

  ciphertext.clear();
  ciphertext.reserve(message.size());
  for (std::size_t offset = 0; offset < message.size();
       offset += kAEADChunkSize) {
    const std::size_t count =
        std::min(kAEADChunkSize, message.size() - offset);
    abe_lsss::ByteString inputBlock = message.getSubset(offset, count);
    if (!check(stream.encryptUpdate(inputBlock, ciphertext), state,
               "Encrypting an AES-GCM block")) {
      return false;
    }
  }
  abe_lsss::ByteString finalBlock;
  return check(stream.encryptFinalize(finalBlock, tag), state,
               "Finalizing AES-GCM encryption");
}

static bool decryptAEAD(abe_lsss::ByteString& ciphertext,
                        abe_lsss::ByteString& iv, abe_lsss::ByteString& tag,
                        const std::shared_ptr<abe_lsss::SymmetricKey>& key,
                        const abe_lsss::ByteString& aad,
                        abe_lsss::ByteString& plaintext,
                        benchmark::State& state) {
  abe_lsss::AES_GCM_Stream stream(DEFAULT_AES_SEC_LEVEL, key);
  if (!check(stream.decryptInit(iv, tag),
             state, "Starting AES-GCM decryption") ||
      !setAAD(stream, aad, state)) {
    return false;
  }

  plaintext.clear();
  plaintext.reserve(ciphertext.size());
  for (std::size_t offset = 0; offset < ciphertext.size();
       offset += kAEADChunkSize) {
    const std::size_t count =
        std::min(kAEADChunkSize, ciphertext.size() - offset);
    abe_lsss::ByteString inputBlock = ciphertext.getSubset(offset, count);
    if (!check(stream.decryptUpdate(inputBlock, plaintext), state,
               "Decrypting an AES-GCM block")) {
      return false;
    }
  }
  return check(stream.decryptFinalize(plaintext), state,
               "Verifying the AES-GCM tag");
}

static bool verifyPlaintext(const abe_lsss::ByteString& plaintext,
                            const abe_lsss::ByteString& expected,
                            benchmark::State& state) {
  if (plaintext.size() != expected.size() ||
      !std::equal(plaintext.begin(), plaintext.end(), expected.begin())) {
    state.SkipWithError("Decrypted payload does not match the original");
    return false;
  }
  return true;
}

static bool wrapAEADKey(BenchmarkContext& data,
                        abe_lsss::ByteString& keyBytes,
                        abe_lsss::Ciphertext& wrappedKey,
                        benchmark::State& state) {
  auto key = std::make_shared<abe_lsss::SymmetricKey>();
  if (!key->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES)) {
    state.SkipWithError("Could not generate an AES-256 key");
    return false;
  }
  keyBytes = key->getKeyBytes();
  return check(data.context->encrypt("MPK", data.policy.get(), keyBytes,
                                    wrappedKey),
               state, "Encrypting the AES key with CP-ABE");
}

static bool unwrapAEADKey(BenchmarkContext& data,
                          abe_lsss::Ciphertext& wrappedKey,
                          abe_lsss::ByteString& keyBytes,
                          benchmark::State& state) {
  return check(data.context->decrypt("MPK", "Alice", keyBytes, wrappedKey),
               state, "Decrypting the AES key with CP-ABE");
}

static std::shared_ptr<abe_lsss::SymmetricKey> makeAEADKey(
    abe_lsss::ByteString& keyBytes) {
  auto key = std::make_shared<abe_lsss::SymmetricKey>();
  key->setSymmetricKey(keyBytes);
  return key;
}

static void BM_DirectABE_Encrypt(benchmark::State& state) {
  BenchmarkContext data;
  if (!initializeBenchmark(state, data)) {
    return;
  }

  abe_lsss::Ciphertext ciphertext;
  for (auto _ : state) {
    if (!check(data.context->encrypt("MPK", data.policy.get(), data.message,
                                     ciphertext),
               state, "Encrypting the message with ABE")) {
      break;
    }
    benchmark::DoNotOptimize(ciphertext);
  }
  if (!state.error_occurred()) {
    abe_lsss::ByteString plaintext;
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

  abe_lsss::Ciphertext ciphertext;
  if (!check(data.context->encrypt("MPK", data.policy.get(), data.message,
                                   ciphertext),
             state, "Preparing the ABE ciphertext")) {
    return;
  }
  abe_lsss::ByteString plaintext;
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

  abe_lsss::ByteString keyBytes, ciphertextBytes, iv, tag, aad;
  abe_lsss::Ciphertext wrappedKey;
  for (auto _ : state) {
    if (!wrapAEADKey(data, keyBytes, wrappedKey, state)) {
      break;
    }
    wrappedKey.getHeader(aad);
    auto key = makeAEADKey(keyBytes);
    if (!encryptAEAD(data.message, key, aad, ciphertextBytes, iv, tag, state)) {
      break;
    }
    benchmark::DoNotOptimize(ciphertextBytes);
  }
  if (!state.error_occurred()) {
    abe_lsss::ByteString recoveredKeyBytes, plaintext;
    if (!unwrapAEADKey(data, wrappedKey, recoveredKeyBytes, state) ||
        !decryptAEAD(ciphertextBytes, iv, tag, makeAEADKey(recoveredKeyBytes),
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

  abe_lsss::ByteString keyBytes, ciphertextBytes, iv, tag, aad;
  abe_lsss::Ciphertext wrappedKey;
  if (!wrapAEADKey(data, keyBytes, wrappedKey, state)) {
    return;
  }
  wrappedKey.getHeader(aad);
  auto encryptionKey = makeAEADKey(keyBytes);
  if (!encryptAEAD(data.message, encryptionKey, aad, ciphertextBytes, iv, tag,
                   state)) {
    return;
  }

  abe_lsss::ByteString serializedKey;
  wrappedKey.exportToBytes(serializedKey);
  abe_lsss::Ciphertext serializedWrappedKey;
  serializedWrappedKey.loadFromBytes(serializedKey);
  abe_lsss::ByteString plaintext;
  for (auto _ : state) {
    abe_lsss::ByteString recoveredKeyBytes;
    if (!unwrapAEADKey(data, serializedWrappedKey, recoveredKeyBytes, state)) {
      break;
    }
    auto decryptionKey = makeAEADKey(recoveredKeyBytes);
    if (!decryptAEAD(ciphertextBytes, iv, tag, decryptionKey, aad, plaintext,
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

struct HybridStreamCiphertext {
  abe_lsss::Ciphertext kem;
  abe_lsss::ByteString iv;
  abe_lsss::ByteString payload;
  abe_lsss::ByteString tag;
};

static bool encryptHybridStream(HybridBenchmarkContext& data,
                                abe_lsss::Scheme scheme,
                                HybridStreamCiphertext& ciphertext,
                                benchmark::State& state) {
  std::unique_ptr<abe_lsss::HybridEncryptStream> stream;
  if (!check(data.context->encryptInit("MPK", encryptionInput(data, scheme),
                                       ciphertext.kem, ciphertext.iv, stream),
             state, "Initializing hybrid stream encryption")) {
    return false;
  }
  ciphertext.payload.clear();
  ciphertext.payload.reserve(data.message.size());
  for (std::size_t offset = 0; offset < data.message.size();
       offset += kAEADChunkSize) {
    const auto count = std::min(kAEADChunkSize, data.message.size() - offset);
    auto input = data.message.getSubset(offset, count);
    abe_lsss::ByteString block;
    if (!check(stream->update(input, block), state, "Encrypting hybrid stream block")) {
      return false;
    }
    ciphertext.payload += block;
  }
  return check(stream->finalize(ciphertext.tag), state,
               "Finalizing hybrid stream encryption");
}

static bool decryptHybridStream(HybridBenchmarkContext& data,
                                HybridStreamCiphertext& ciphertext,
                                abe_lsss::ByteString& plaintext,
                                benchmark::State& state) {
  std::unique_ptr<abe_lsss::HybridDecryptStream> stream;
  if (!check(data.context->decryptInit("MPK", "Alice", ciphertext.kem,
                                       ciphertext.iv, stream),
             state, "Initializing hybrid stream decryption")) {
    return false;
  }
  plaintext.clear();
  plaintext.reserve(ciphertext.payload.size());
  for (std::size_t offset = 0; offset < ciphertext.payload.size();
       offset += kAEADChunkSize) {
    const auto count = std::min(kAEADChunkSize, ciphertext.payload.size() - offset);
    auto input = ciphertext.payload.getSubset(offset, count);
    abe_lsss::ByteString block;
    if (!check(stream->update(input, block), state, "Decrypting hybrid stream block")) {
      plaintext.zeroize();
      return false;
    }
    plaintext += block;
  }
  if (!check(stream->finalize(ciphertext.tag), state,
             "Verifying hybrid stream tag")) {
    plaintext.zeroize();
    return false;
  }
  return true;
}

static void BM_Hybrid_Encrypt(benchmark::State& state, abe_lsss::Scheme scheme) {
  HybridBenchmarkContext data;
  if (!initializeBenchmark(state, data, scheme)) return;
  abe_lsss::Ciphertext ciphertext;
  for (auto _ : state) {
    if (!check(data.context->encrypt("MPK", encryptionInput(data, scheme),
                                     data.message, ciphertext),
               state, "Encrypting hybrid payload")) {
      break;
    }
    benchmark::DoNotOptimize(ciphertext);
  }
  if (!state.error_occurred()) {
    abe_lsss::ByteString plaintext;
    if (!check(data.context->decrypt("MPK", "Alice", plaintext, ciphertext),
               state, "Verifying hybrid encryption") ||
        !verifyPlaintext(plaintext, data.message, state)) return;
  }
  state.SetBytesProcessed(static_cast<int64_t>(data.message.size()) * state.iterations());
}

static void BM_Hybrid_Decrypt(benchmark::State& state, abe_lsss::Scheme scheme) {
  HybridBenchmarkContext data;
  if (!initializeBenchmark(state, data, scheme)) return;
  abe_lsss::Ciphertext ciphertext;
  if (!check(data.context->encrypt("MPK", encryptionInput(data, scheme),
                                   data.message, ciphertext),
             state, "Preparing hybrid ciphertext")) return;
  abe_lsss::ByteString plaintext;
  for (auto _ : state) {
    if (!check(data.context->decrypt("MPK", "Alice", plaintext, ciphertext),
               state, "Decrypting hybrid payload")) break;
    benchmark::DoNotOptimize(plaintext);
  }
  if (!state.error_occurred() &&
      !verifyPlaintext(plaintext, data.message, state)) return;
  state.SetBytesProcessed(static_cast<int64_t>(data.message.size()) * state.iterations());
}

static void BM_Hybrid_Stream_Encrypt(benchmark::State& state, abe_lsss::Scheme scheme) {
  HybridBenchmarkContext data;
  if (!initializeBenchmark(state, data, scheme)) return;
  HybridStreamCiphertext ciphertext;
  for (auto _ : state) {
    if (!encryptHybridStream(data, scheme, ciphertext, state)) break;
    benchmark::DoNotOptimize(ciphertext.payload);
  }
  if (!state.error_occurred()) {
    abe_lsss::ByteString plaintext;
    if (!decryptHybridStream(data, ciphertext, plaintext, state) ||
        !verifyPlaintext(plaintext, data.message, state)) return;
  }
  state.SetBytesProcessed(static_cast<int64_t>(data.message.size()) * state.iterations());
}

static void BM_Hybrid_Stream_Decrypt(benchmark::State& state, abe_lsss::Scheme scheme) {
  HybridBenchmarkContext data;
  if (!initializeBenchmark(state, data, scheme)) return;
  HybridStreamCiphertext ciphertext;
  if (!encryptHybridStream(data, scheme, ciphertext, state)) return;
  abe_lsss::ByteString plaintext;
  for (auto _ : state) {
    if (!decryptHybridStream(data, ciphertext, plaintext, state)) break;
    benchmark::DoNotOptimize(plaintext);
  }
  if (!state.error_occurred() &&
      !verifyPlaintext(plaintext, data.message, state)) return;
  state.SetBytesProcessed(static_cast<int64_t>(data.message.size()) * state.iterations());
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
BENCHMARK_CAPTURE(BM_Hybrid_Encrypt, CP_WATERS, abe_lsss::cp_waters)->Apply(registerPayloadSize);
BENCHMARK_CAPTURE(BM_Hybrid_Encrypt, KP_GPSW, abe_lsss::kp_gpsw)->Apply(registerPayloadSize);
BENCHMARK_CAPTURE(BM_Hybrid_Decrypt, CP_WATERS, abe_lsss::cp_waters)->Apply(registerPayloadSize);
BENCHMARK_CAPTURE(BM_Hybrid_Decrypt, KP_GPSW, abe_lsss::kp_gpsw)->Apply(registerPayloadSize);
BENCHMARK_CAPTURE(BM_Hybrid_Stream_Encrypt, CP_WATERS, abe_lsss::cp_waters)->Apply(registerPayloadSize);
BENCHMARK_CAPTURE(BM_Hybrid_Stream_Encrypt, KP_GPSW, abe_lsss::kp_gpsw)->Apply(registerPayloadSize);
BENCHMARK_CAPTURE(BM_Hybrid_Stream_Decrypt, CP_WATERS, abe_lsss::cp_waters)->Apply(registerPayloadSize);
BENCHMARK_CAPTURE(BM_Hybrid_Stream_Decrypt, KP_GPSW, abe_lsss::kp_gpsw)->Apply(registerPayloadSize);

int main(int argc, char** argv) {
  abe_lsss::initialize();
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  abe_lsss::shutdown();
  return 0;
}
