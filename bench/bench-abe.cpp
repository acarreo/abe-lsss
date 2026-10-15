#include <benchmark/benchmark.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <math.h>
#include <random>

#include <abe_lsss.h>
#include "../utils/utils.h"
#include "policy_generators.h"

// #define TEST_MSG_LEN (1024 * 1024) // 1MB
#define TEST_MSG_LEN 32 // 32 bytes -> 256 bits, which can be used for symmetric keys

using namespace std;

// Use the function OpenABE_convertSchemeIDToString from utils to convert scheme
// enum to string for better readability in benchmarks

enum class PolicyType {
    Mixed,
    Balanced,
};

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
    PolicyType policy_type;
} BenchmarkInput;

static const char* getPolicyTypeLabel(PolicyType policyType) {
    return policyType == PolicyType::Mixed ? "mixed" : "balanced";
}

static void addInputSizeCounters(benchmark::State& state, const BenchmarkInput& input) {
    const bool isCPABE = input.scheme == OpenABE_SCHEME_CP_WATERS;
    const string& policy = isCPABE ? input.enc_input : input.key_input;
    const string& attributes = isCPABE ? input.key_input : input.enc_input;
    const auto policyTree = createPolicyTree(policy);
    const auto attributeList = createAttributeList(attributes);
    OpenABELSSS lsss;
    const bool satisfied = lsss.recoverCoefficients(policyTree.get(), attributeList.get());
    assert(satisfied);

    state.counters["policy_size"] = policyTree->getAttrCompleteSet().size();
    state.counters["attr_size"] = attributeList->getAttributeList()->size();
    state.counters["msa_size"] = lsss.getRows().size(); // Minimum Satisfying Attribute set size
}


static void BM_Encrypt(benchmark::State& state, BenchmarkInput input) {
    auto schemeContext = createContextABESchemeCPA(input.scheme);
    schemeContext->generateParams("MPK", "MSK");
    auto encInput = getEncInput(input.scheme, input.enc_input);
    addInputSizeCounters(state, input);
    state.SetLabel(getPolicyTypeLabel(input.policy_type));

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
    addInputSizeCounters(state, input);
    state.SetLabel(getPolicyTypeLabel(input.policy_type));

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

static string createPolicy(PolicyType policyType, int attributeCount) {
    if (policyType == PolicyType::Balanced) {
        return getBalancedOpenABETree(0, attributeCount - 1);
    }
    return createMixedPolicy(0, attributeCount);
}

static string formatAttributeList(const vector<string>& attributeList) {
    string attributes = "|";
    for (const string& attribute : attributeList) {
        attributes += attribute + "|";
    }
    return attributes;
}

static string createAttributeListString(int attributeCount, int policyAttributeCount) {
    const int totalAttributeCount = max(attributeCount, policyAttributeCount);
    vector<string> attributeList;
    attributeList.reserve(totalAttributeCount);

    for (int i = 0; i < policyAttributeCount; ++i) {
        attributeList.push_back("Attr_" + to_string(i));
    }
    for (int i = policyAttributeCount; i < totalAttributeCount; ++i) {
        attributeList.push_back("Extra_" + to_string(i - policyAttributeCount));
    }

    static random_device randomDevice;
    static mt19937 randomGenerator(randomDevice());
    shuffle(attributeList.begin(), attributeList.end(), randomGenerator);

    return formatAttributeList(attributeList);
}

static BenchmarkInput createVaryingInput(OpenABE_SCHEME scheme,
        int policyAttributeCount, int attributeListCount, PolicyType policyType) {
    const string policy = createPolicy(policyType, policyAttributeCount);
    const string attributes = createAttributeListString(attributeListCount, policyAttributeCount);
    const bool isCPABE = scheme == OpenABE_SCHEME_CP_WATERS;

    return {
        .scheme = scheme,
        .enc_input = isCPABE ? policy : attributes,
        .key_input = isCPABE ? attributes : policy,
        .msg_size = TEST_MSG_LEN,
        .expect_pass = true,
        .policy_type = policyType,
    };
}

static void BM_ABE_CompleteCycle(benchmark::State& state, BenchmarkInput input) {
    addInputSizeCounters(state, input);
    state.SetLabel(getPolicyTypeLabel(input.policy_type));

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

static void registerVaryingInputBenchmarks(OpenABE_SCHEME scheme,
        const vector<int>& policySizes, const vector<int>& attributeListSizes) {
    const string schemeName = scheme == OpenABE_SCHEME_CP_WATERS ? "CP-ABE" : "KP-ABE";

    // CP-ABE encrypts under a policy; KP-ABE encrypts under an attribute list.
    if (scheme == OpenABE_SCHEME_CP_WATERS) {
        for (PolicyType policyType : {PolicyType::Mixed, PolicyType::Balanced}) {
            for (int policySize : policySizes) {
                BenchmarkInput input =
                    createVaryingInput(scheme, policySize, 1, policyType);
                benchmark::RegisterBenchmark("BM_Encrypt/" + schemeName, BM_Encrypt, input);
            }
        }
    } else {
        for (int attributeListSize : attributeListSizes) {
            BenchmarkInput input = createVaryingInput(
                scheme, 1, attributeListSize, PolicyType::Mixed);
            benchmark::RegisterBenchmark("BM_Encrypt/" + schemeName, BM_Encrypt, input);
        }
    }

    if (policySizes.empty() || attributeListSizes.empty()) {
        return;
    }

    if (scheme == OpenABE_SCHEME_CP_WATERS) {
        const int fixedPolicySize = *max_element(policySizes.begin(), policySizes.end());
        for (PolicyType policyType : {PolicyType::Mixed, PolicyType::Balanced}) {
            for (int extraAttributeCount : attributeListSizes) {
                BenchmarkInput input = createVaryingInput(
                    scheme, fixedPolicySize, fixedPolicySize + extraAttributeCount, policyType);
                benchmark::RegisterBenchmark("BM_Decrypt/" + schemeName, BM_Decrypt, input);
            }
        }
    } else {
        const int fixedAttributeListSize = *max_element(attributeListSizes.begin(), attributeListSizes.end());
        for (PolicyType policyType : {PolicyType::Mixed, PolicyType::Balanced}) {
            for (int policySize : policySizes) {
                BenchmarkInput input = createVaryingInput(
                    scheme, policySize, fixedAttributeListSize, policyType);
                benchmark::RegisterBenchmark("BM_Decrypt/" + schemeName, BM_Decrypt, input);
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

    static const vector<int> policySizes = {1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    static const vector<int> attributeListSizes = {1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    registerVaryingInputBenchmarks(OpenABE_SCHEME_CP_WATERS, policySizes, attributeListSizes);
    registerVaryingInputBenchmarks(OpenABE_SCHEME_KP_GPSW, policySizes, attributeListSizes);

    // Run benchmarks
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();

    ShutdownOpenABE();
    return 0;
}
