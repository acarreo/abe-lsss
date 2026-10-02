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

#define TEST_MSG_LEN    32

using namespace std;

string createAttribute(int i) {
		stringstream ss;
		ss << "Attr_" << i;
		return ss.str();
}

bool generatetAttributeList(int max, vector<string> & attrList) {
    if(max <= 0) { return false; }

    attrList.clear();
    for(int i = 0; i <= max; i++) {
        attrList.push_back( createAttribute(i) );
    }
    return true;
}

string convertToAttributeListString(vector<string>& attr_list) {
    string a_str = "|";
    for (auto a : attr_list) {
    	a_str += a + "|";
    }
    return a_str;
}

// returns an evenly distributed / balanced policy tree
string getBalancedOpenABETree(int start, int end) {
    if(start == end) { return createAttribute(start); }

    int mid = ceil((start + (end - start) / 2.0));
    if(mid == 0) {
        return "(" + createAttribute(start) + " and " + createAttribute(end) + ")";
    }
    else {
        return "(" + getBalancedOpenABETree(start, mid-1) + " and " + getBalancedOpenABETree(mid, end) + ")";
    }
}

// returns a right-sided skewed policy tree
string getOpenABEPolicyString(int max) {
    string policystr;
    if(max >= 2) {
        policystr = "(" + createAttribute(0) + " and " + createAttribute(1) + ")";
    }
    else if(max == 1) {
        policystr = createAttribute(0);
    }

    for(int i = 2; i < max; i++) {
        policystr = "(" + policystr + " and " + createAttribute(i) + ")";
    }

    return policystr;
}

bool runLSSSTest(string policy_str, string attr_list_str, bool verbose = false) {
    // Create a pairing object
    OpenABEPairing pairing;

    unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str);
    if(verbose) {
        cout << "Policy: " << policy->toString() << endl;
    }
    ZP secret = pairing.randomZP();
    // Compute the secret shares
    OpenABELSSS lsss;
    lsss.shareSecret(policy.get(), secret);
    // Get the resulting shares
    OpenABELSSSRowMap shares = lsss.getRows();
    if(verbose) {
        cout << "Obtained " << shares.size() << " secret shares" << endl;
    }

    OpenABELSSS recoveryLsss;

    // OpenABEAttributeList *attrList = new OpenABEAttributeList(S.size(), S);
    unique_ptr<OpenABEAttributeList> attrList = createAttributeList(attr_list_str);
    if(verbose) {
    	cout << "AttrList: " << attrList->toString() << endl;
    }
    if(recoveryLsss.recoverCoefficients(policy.get(), attrList.get()) == false)
        return false;
    OpenABELSSSRowMap coefficients = recoveryLsss.getRows();
    if(verbose) {
        cout << "Recovered " << coefficients.size() << " coefficients." << endl;
    }

    ZP recSecret = recoveryLsss.LSSStestSecretRecovery(coefficients,  shares);
    return secret == recSecret;
}


static const std::vector<int64_t> SIZES = {1, 10, 100, 1000};

static void BM_LSSS(benchmark::State& state) {
	int attrCount = state.range(0);
	string policy_str = getBalancedOpenABETree(0, attrCount);
	vector<string> attrList;
	generatetAttributeList(attrCount, attrList);
	string attr_list_str = convertToAttributeListString(attrList);

	for (auto _ : state) {
		assert(runLSSSTest(policy_str, attr_list_str, false) == true);
	}
}

BENCHMARK(BM_LSSS)->ArgsProduct({SIZES});

enum ExtraLayout { EXTRA_FIRST = 0, EXTRA_INTERLEAVED = 1 };

// Args: {policy size, number of extra attributes, ExtraLayout, satisfied (1) or not (0)}
static void BM_recoverCoefficients(benchmark::State& state) {
	int attrCount = state.range(0);
	int extras = state.range(1);
	int layout = state.range(2);
	bool satisfied = state.range(3) != 0;

	string policy_str = getBalancedOpenABETree(0, attrCount);
	unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str);

	// matchAttribute is a linear search, so extra attributes only cost time when placed before policy attributes
	vector<string> attrList;
	if (layout == EXTRA_FIRST) {
		for (int e = 0; e < extras; e++) { attrList.push_back("Extra_" + to_string(e)); }
	}
	for (int i = 0; i <= attrCount; i++) {
		// An AND-only policy is unsatisfied as soon as one of its attributes is missing
		if (satisfied || i != attrCount) { attrList.push_back(createAttribute(i)); }
		if (layout == EXTRA_INTERLEAVED) {
			for (int e = (int)((long)i * extras / (attrCount + 1)); e < (int)((long)(i + 1) * extras / (attrCount + 1)); e++) {
				attrList.push_back("Extra_" + to_string(e));
			}
		}
	}
	unique_ptr<OpenABEAttributeList> attrs = createAttributeList(convertToAttributeListString(attrList));

	OpenABELSSS lsss;
	for (auto _ : state) {
		bool res = lsss.recoverCoefficients(policy.get(), attrs.get());
		benchmark::DoNotOptimize(res);
		if (res != satisfied) {
			state.SkipWithError("unexpected recoverCoefficients result");
			break;
		}
	}
	static const char* layoutNames[] = {"extra_first", "extra_interleaved"};
	state.SetLabel(string(layoutNames[layout]) + (satisfied ? " satisfied" : " unsatisfied"));
}

BENCHMARK(BM_recoverCoefficients)
	->ArgsProduct({SIZES, {0, 10, 100, 1000}, {EXTRA_FIRST, EXTRA_INTERLEAVED}, {0, 1}});


int main(int argc, char** argv) {
	InitializeOpenABE();

  ::benchmark::Initialize(&argc, argv);
  ::benchmark::RunSpecifiedBenchmarks();

	ShutdownOpenABE();

  return 0;
}
