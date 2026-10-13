#include <benchmark/benchmark.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
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
    bool expect_pass;
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

static string createMixedPolicy(int firstAttribute, int attributeCount, int depth = 0) {
    if (attributeCount == 1) {
        return "Attr_" + to_string(firstAttribute);
    }

    int leftAttributeCount = attributeCount / 2;
    const char* gate = depth % 2 == 0 ? " and " : " or ";
    return "(" + createMixedPolicy(firstAttribute, leftAttributeCount, depth + 1) +
        gate + createMixedPolicy(firstAttribute + leftAttributeCount,
            attributeCount - leftAttributeCount, depth + 1) + ")";
}

static string createAttributeListString(int attributeCount, int policyAttributeCount,
        bool extrasFirst = false) {
    string attributes = "|";
    if (extrasFirst) {
        for (int i = policyAttributeCount; i < attributeCount; ++i) {
            attributes += "Extra_" + to_string(i - policyAttributeCount) + "|";
        }
        for (int i = 0; i < policyAttributeCount; ++i) {
            attributes += "Attr_" + to_string(i) + "|";
        }
    } else {
        for (int i = 0; i < attributeCount; ++i) {
            attributes += "Attr_" + to_string(i) + "|";
        }
    }
    return attributes;
}

static BenchmarkInput createVaryingInput(OpenABE_SCHEME scheme,
        int policyAttributeCount, int attributeListCount, bool extrasFirst = false) {
    const string policy = createMixedPolicy(0, policyAttributeCount);
    const string attributes = createAttributeListString(
        attributeListCount, policyAttributeCount, extrasFirst);
    const bool isCPABE = scheme == OpenABE_SCHEME_CP_WATERS;

    if (policyAttributeCount < 10 || attributeListCount < 10) {
        std::cout << "Benchmark input for scheme: " << OpenABE_convertSchemeIDToString(scheme)
            << ", policy attributes: " << policyAttributeCount
            << ", attribute list: " << attributeListCount
            << ", extras first: " << (extrasFirst ? "true" : "false") << std::endl;
    }

    return {
        .scheme = scheme,
        .enc_input = isCPABE ? policy : attributes,
        .key_input = isCPABE ? attributes : policy,
        .msg_size = TEST_MSG_LEN,
        .expect_pass = true
    };
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

static void registerVaryingInputBenchmarks() {
    static const vector<int> POLICY_SIZES = {1, 2, 4, 8, 16, 32, 64};
    static const vector<int> ATTRIBUTE_LIST_SIZES = {1, 10, 100, 1000, 10000};

    for (OpenABE_SCHEME scheme : {OpenABE_SCHEME_CP_WATERS, OpenABE_SCHEME_KP_GPSW}) {
        const string schemeName = scheme == OpenABE_SCHEME_CP_WATERS ? "CP-ABE" : "KP-ABE";

        // CP-ABE encrypts under a policy; KP-ABE encrypts under an attribute list.
        if (scheme == OpenABE_SCHEME_CP_WATERS) {
            for (int policySize : POLICY_SIZES) {
                BenchmarkInput input = createVaryingInput(scheme, policySize, 1);
                benchmark::RegisterBenchmark("BM_Encrypt/" + schemeName + "/policy_" +
                    to_string(policySize), BM_Encrypt, input);
            }
        } else {
            for (int attributeListSize : ATTRIBUTE_LIST_SIZES) {
                BenchmarkInput input = createVaryingInput(scheme, 1, attributeListSize);
                benchmark::RegisterBenchmark("BM_Encrypt/" + schemeName + "/attributes_" +
                    to_string(attributeListSize), BM_Encrypt, input);
            }
        }

        // Decryption depends on both dimensions: policy leaves and available
        // attributes, regardless of which is the encryption or key input.
        for (int policySize : POLICY_SIZES) {
            for (int attributeListSize : ATTRIBUTE_LIST_SIZES) {
                if (attributeListSize < policySize) {
                    continue;
                }
                BenchmarkInput input = createVaryingInput(
                    scheme, policySize, attributeListSize, true);
                benchmark::RegisterBenchmark("BM_Decrypt/" + schemeName + "/policy_" +
                    to_string(policySize) + "/attributes_" + to_string(attributeListSize),
                    BM_Decrypt, input);
            }
        }
    }
}


int main(int argc, char** argv) {
    InitializeOpenABE();

#if 0
    BenchmarkInput input_CP = {
        .scheme = OpenABE_SCHEME_CP_WATERS,
        .enc_input = "((Alice or Bob) and (Charlie or David))",
        .key_input = "Alice|Charlie|Dave|Eve",
        .msg_size = TEST_MSG_LEN,
        .expect_pass = true
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
        .msg_size = TEST_MSG_LEN,
        .expect_pass = true
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
#endif

    registerVaryingInputBenchmarks();

    // Run benchmarks
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();

    ShutdownOpenABE();
    return 0;
}
