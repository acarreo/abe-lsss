#include <benchmark/benchmark.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <math.h>

#include <abe_lsss.h>
#include "../utils/utils.h"

// #define TEST_MSG_LEN (1024 * 1024) // 1MB
#define TEST_MSG_LEN 32 // 32 bytes -> 256 bits, which can be used for symmetric keys

using namespace std;

// Use the function OpenABE_convertSchemeIDToString from utils to convert scheme
// enum to string for better readability in benchmarks

/**
 * Benchmark input configuration structure
 * Encapsulates all parameters for a benchmark run
 */
typedef struct {
    OpenABE_SCHEME scheme;
    string enc_input;
    string key_input;
    int msg_size;
    bool expect_pass = true;
} BenchmarkInput;


static void BM_Encrypt(benchmark::State& state, BenchmarkInput input) {
    auto schemeContext = createContextABESchemeCPA(input.scheme);
    schemeContext->generateParams("MPK", "MSK");
    auto encInput = getEncInput(input.scheme, input.enc_input);

    OpenABEByteString plaintext;
    getRandomBytes(plaintext, input.msg_size);

    for (auto _ : state) {
        OpenABECiphertext ct;
        schemeContext->encrypt("MPK", encInput.get(), plaintext, ct);
    }

    // Count the number of encryption operations performed per second
    state.SetItemsProcessed(state.iterations());
}

static void BM_Decrypt(benchmark::State& state, BenchmarkInput input) {
    auto schemeContext = createContextABESchemeCPA(input.scheme);
    schemeContext->generateParams("MPK", "MSK");

    OpenABEByteString plaintext;
    auto encInput = getEncInput(input.scheme, input.enc_input);
    getRandomBytes(plaintext, input.msg_size);

		OpenABECiphertext ct;
		schemeContext->encrypt("MPK", encInput.get(), plaintext, ct);

    auto keyInput = getKeyInput(input.scheme, input.key_input);
		schemeContext->keygen(keyInput.get(), "DecKey", "MPK", "MSK");

    for (auto _ : state) {
        OpenABEByteString recovered;
        schemeContext->decrypt("MPK", "DecKey", recovered, ct);

        // Optional: Verify correctness (can be commented out for pure performance benchmarking)
        assert((plaintext == recovered) == input.expect_pass);
    }

    // Count the number of decryption operations performed per second
    state.SetItemsProcessed(state.iterations());
}

static void BM_ABE_CompleteCycle(benchmark::State& state, BenchmarkInput input) {
    for (auto _ : state) {
        auto schemeContext = createContextABESchemeCPA(input.scheme);
        schemeContext->generateParams("MPK", "MSK");

        OpenABEByteString plaintext;
        getRandomBytes(plaintext, input.msg_size);

        auto encInput = getEncInput(input.scheme, input.enc_input);
        auto keyInput = getKeyInput(input.scheme, input.key_input);

        schemeContext->keygen(keyInput.get(), "DecKey", "MPK", "MSK");

        OpenABECiphertext ct;
        schemeContext->encrypt("MPK", encInput.get(), plaintext, ct);

        OpenABEByteString recovered;
        schemeContext->decrypt("MPK", "DecKey", recovered, ct);

        // Optional: Verify correctness (can be commented out for pure performance benchmarking)
        assert((plaintext == recovered) == input.expect_pass);
    }
}


static void BM_Encrypt_VaryingFileSize(benchmark::State& state) {
    auto schemeContext = createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);
    schemeContext->generateParams("testMPK", "testMSK");

    int msgSize = state.range(0);  // Get parameter: 1024, 16384, 262144, 1048576
    OpenABEByteString plaintext;
    getRandomBytes(plaintext, msgSize);

    auto encInput = createPolicyTree("(Alice and Bob) or (Charlie and David)");

    for (auto _ : state) {
        OpenABECiphertext ct;
        schemeContext->encrypt("testMPK", encInput.get(), plaintext, ct);
    }
}

BENCHMARK(BM_Encrypt_VaryingFileSize)
    ->RangeMultiplier(16)
    ->Range(1024, 1024 * 1024);

static void BM_Decrypt_VaryingFileSize(benchmark::State& state) {
    auto schemeContext = createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);
    schemeContext->generateParams("testMPK", "testMSK");

    int msgSize = state.range(0);
    OpenABEByteString plaintext;
    getRandomBytes(plaintext, msgSize);

    auto encInput = createPolicyTree("(Alice and Bob) or (Charlie and David)");
    OpenABECiphertext ct;
    schemeContext->encrypt("testMPK", encInput.get(), plaintext, ct);

    auto keyInput = createAttributeList("Alice|Bob");
    schemeContext->keygen(keyInput.get(), "DecKey", "testMPK", "testMSK");

    for (auto _ : state) {
        OpenABEByteString recovered;
        schemeContext->decrypt("testMPK", "DecKey", recovered, ct);
    }
}

BENCHMARK(BM_Decrypt_VaryingFileSize)
    ->RangeMultiplier(16)
    ->Range(1024, 1024 * 1024);


int main(int argc, char** argv) {
    InitializeOpenABE();

    BenchmarkInput input_CP = {
        .scheme = OpenABE_SCHEME_CP_WATERS,
        .enc_input = "((Alice or Bob) and (Charlie or David))",
        .key_input = "Alice|Charlie|Dave|Eve",
        .msg_size = TEST_MSG_LEN
    };

    BenchmarkInput input_CP_policyNotSatisfied = {
        .scheme = OpenABE_SCHEME_CP_WATERS,
        .enc_input = "((Alice or Bob) and (Charlie or David))",
        .key_input = "Eve|Frank|Grace|Henry",
        .msg_size = TEST_MSG_LEN,
        .expect_pass = false
    };

    BenchmarkInput input_KP = {
        .scheme = OpenABE_SCHEME_KP_GPSW,
        .enc_input = "Alice|Charlie|Dave|Eve",
        .key_input = "((Alice or Bob) and (Charlie or David))",
        .msg_size = TEST_MSG_LEN
    };

    BenchmarkInput input_KP_policyNotSatisfied = {
        .scheme = OpenABE_SCHEME_KP_GPSW,
        .enc_input = "Eve|Frank|Grace|Henry",
        .key_input = "((Alice or Bob) and (Charlie or David))",
        .msg_size = TEST_MSG_LEN,
        .expect_pass = false
    };

    benchmark::RegisterBenchmark("BM_ABE_CompleteCycle/CP-ABE", BM_ABE_CompleteCycle, input_CP);
    benchmark::RegisterBenchmark("BM_ABE_CompleteCycle/KP-ABE", BM_ABE_CompleteCycle, input_KP);
    benchmark::RegisterBenchmark("BM_ABE_CompleteCycle/CP-ABE_PolicyNotSatisfied", BM_ABE_CompleteCycle, input_CP_policyNotSatisfied);
    benchmark::RegisterBenchmark("BM_ABE_CompleteCycle/KP-ABE_PolicyNotSatisfied", BM_ABE_CompleteCycle, input_KP_policyNotSatisfied);

    benchmark::RegisterBenchmark("BM_Encrypt/CP-ABE", BM_Encrypt, input_CP);
    benchmark::RegisterBenchmark("BM_Encrypt/KP-ABE", BM_Encrypt, input_KP);
    benchmark::RegisterBenchmark("BM_Decrypt/CP-ABE", BM_Decrypt, input_CP);
    benchmark::RegisterBenchmark("BM_Decrypt/KP-ABE", BM_Decrypt, input_KP);

    // Run benchmarks
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();

    ShutdownOpenABE();
    return 0;
}
