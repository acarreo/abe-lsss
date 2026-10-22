#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <math.h>
#include <gtest/gtest.h>

#include <abe_lsss.h>

#include "../utils/utils.h"

using namespace std;

#define TEST_MSG_LEN    32

#define COMMA   ','
#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)
#define TESTSUITE_DESCRIPTION(desc) ::testing::Test::RecordProperty("description", desc)


/* Note on CPA security tests:
 * Decryption returns OpenABE_NOERROR in either a successful or failed decryption attempt except
 * if an exception is triggered due to invalid inputs. This is by design.
 */

namespace {

class Input {
public:
    Input(OpenABE_SCHEME scheme, const string enc_input,
          const string key, bool expect_pass,
          bool verbose = true) {
            // We set verbose to true by default for better visibility into test
            // cases, but it can be set to false for cleaner test output
        scheme_type    = scheme;
        func_input = enc_input;
        key_input = key;
        expect_pass_ = expect_pass;
        verbose_   = verbose;
    }
    ~Input() {};
    OpenABE_SCHEME scheme_type;
    string func_input, policy_str, key_input;
    vector<string> attr_list;
    bool verbose_, expect_pass_;
};

class CPASecurityForSchemeTest : public ::testing::TestWithParam<Input> {
protected:
    virtual void SetUp() {
        getRandomBytes(plaintext, TEST_MSG_LEN);
        MPK = "testMPK";
        MSK = "testMSK";
        AUTH1MPK = "auth1", AUTH1MSK = "auth1MSK";
        AUTH2MPK = "auth2", AUTH2MSK = "auth2MSK";
    }

    unique_ptr<OpenABEFunctionInput> getEncInput(OpenABE_SCHEME type, const string func_input) {
        if(type == OpenABE_SCHEME_CP_WATERS)
            return createPolicyTree(func_input);
        else if(type == OpenABE_SCHEME_KP_GPSW)
            return createAttributeList(func_input);
        return nullptr;
    }

    unique_ptr<OpenABEFunctionInput> getKeyInput(OpenABE_SCHEME type, string key_input) {
        if(type == OpenABE_SCHEME_CP_WATERS)
            return createAttributeList(key_input);
        else if(type == OpenABE_SCHEME_KP_GPSW)
            return createPolicyTree(key_input);
        return nullptr;
    }

    const string printScheme(OpenABE_SCHEME type) {
        switch(type) {
            case OpenABE_SCHEME_CP_WATERS:
                return "CP-ABE"; break;
            case OpenABE_SCHEME_KP_GPSW:
                return "KP-ABE"; break;
            default:
                break;
        }
        return "None";
    }

    OpenABEByteString mpkBlob, mskBlob, skBlob, ctBlob;
    OpenABEByteString plaintext, plaintext1;
    string MPK, MSK, AUTH1MPK, AUTH1MSK, AUTH2MPK, AUTH2MSK;
};


/* Unit tests for CPA scheme contexts */
TEST_P(CPASecurityForSchemeTest, testWorkingExamples) {
    Input input = GetParam();
    TEST_DESCRIPTION("Testing CPA-secure " + printScheme(input.scheme_type) + " scheme with Key: '" + \
    		input.key_input + "' and Enc: '" + input.func_input + "'");
    OpenABECiphertext ciphertext, ciphertext2;
    cout << "* Testing CPA security for " << printScheme(input.scheme_type) << " schemes..." << endl;
    unique_ptr<OpenABEContextSchemeCPA> schemeContext = createContextABESchemeCPA(input.scheme_type);

    ASSERT_TRUE(schemeContext != nullptr);

    // Generate a set of parameters for an ABE authority
    ASSERT_TRUE(schemeContext->generateParams(MPK, MSK) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->exportKey(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->exportKey(MSK, mskBlob) == OpenABE_NOERROR);

    ASSERT_TRUE(schemeContext->deleteKey(MPK) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->deleteKey(MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(schemeContext->loadMasterPublicParams(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->loadMasterSecretParams(MSK, mskBlob) == OpenABE_NOERROR);

    // encrypt under the specified functional input
    unique_ptr<OpenABEFunctionInput> encInput = getEncInput(input.scheme_type, input.func_input);
    ASSERT_TRUE(schemeContext->encrypt(MPK, encInput.get(), plaintext, ciphertext) == OpenABE_NOERROR);

    ciphertext.exportToBytes(ctBlob);
    ciphertext2.loadFromBytes(ctBlob);
    // ASSERT_TRUE(ciphertext == ciphertext2);

    OpenABEByteString ctBlob2Debug;
    ciphertext2.exportToBytes(ctBlob2Debug);
    // verify header is thesame
    OpenABEByteString hdr1, hdr2;
    ciphertext.getHeader(hdr1);
    ciphertext2.getHeader(hdr2);
    ASSERT_TRUE(hdr1 == hdr2);

    // for both auth1 and auth2
    unique_ptr<OpenABEFunctionInput> keyInput = getKeyInput(input.scheme_type, input.key_input);

    ASSERT_TRUE(schemeContext->keygen((OpenABEFunctionInput *)keyInput.get(), "DecKey", MPK, MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(schemeContext->exportKey("DecKey", skBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->deleteKey("DecKey") == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->loadUserSecretParams("DecKey", skBlob) == OpenABE_NOERROR);

    // Decrypt the ciphertext with multiple keys
    OpenABE_ERROR result = schemeContext->decrypt(MPK, "DecKey", plaintext1, ciphertext2);

    if(input.expect_pass_) {
        ASSERT_TRUE(result == OpenABE_NOERROR);
        ASSERT_TRUE(plaintext == plaintext1);
    } else {
        ASSERT_FALSE(result == OpenABE_NOERROR);
        ASSERT_FALSE(plaintext == plaintext1);
    }

    if (input.verbose_) {
        cout << "\nInput Plaintext: " << plaintext.toHex() << endl;
    	cout << "Enc Input used: " << input.func_input << endl;
    	cout << "Key Input used: " << input.key_input << endl;
    	cout << "Rec Plaintext: " << plaintext1.toHex() << endl;
    	cout << "Test expected to pass: " << (input.expect_pass_ ? "true" : "false") << endl << endl;
    }
}

}


INSTANTIATE_TEST_CASE_P(ABETestBase, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Alice|Charlie", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|David", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETestUsingDates, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "Alice and Date = May 1-10, 2016", "Alice|Date=May 5, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "Date < December 31, 2026 and (Alice or Bob)", "Bob|Date=May 8, 2026", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and Date = May 1-10, 2016)", "Bob|Eve|Date=May 12, 2016", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Charlie|Date = June 12, 2014", "(Date = June 10-20, 2014 and (Charlie or David))", true),
    Input(OpenABE_SCHEME_KP_GPSW, "David|Date = June 25, 2025", "((David or Bob) and (Date >= January 1, 2025 and Date <= December 31, 2025))", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|Date = June 30, 2014", "((Alice and Date = June 21-28, 2014) and Charlie)", false)
));


#if 0
class SatInput {
public:
    SatInput(const string policy_str, const string attr_list, bool expect_pass) {
    	policy_str_ = policy_str;
    	attr_list_ = attr_list;
        expect_pass_ = expect_pass;
        verbose_   = false;
    }
    ~SatInput() {};
    string policy_str_, attr_list_;
    bool verbose_, expect_pass_;
};

class CheckIfSatisfiedTests : public ::testing::TestWithParam<SatInput> {
protected:
    virtual void SetUp() {}
};

TEST_P(CheckIfSatisfiedTests, testWorkingExamples) {
    SatInput input = GetParam();
    TEST_DESCRIPTION("Checking sat for: '" + input.policy_str_ + "' sat by '" + input.attr_list_ + "'");

    unique_ptr<OpenABEPolicy> policy = createPolicyTree(input.policy_str_);
    ASSERT_TRUE(policy != nullptr);
    unique_ptr<OpenABEAttributeList> attr_list = createAttributeList(input.attr_list_);
    ASSERT_TRUE(attr_list != nullptr);
    pair<bool,int> res = checkIfSatisfied(policy.get(), attr_list.get());
    if (input.expect_pass_) {
        ASSERT_TRUE(res.first);
    } else {
        ASSERT_FALSE(res.first);
    }
}

INSTANTIATE_TEST_CASE_P(CheckSat1, CheckIfSatisfiedTests,
    ::testing::Values(
    // test standard or/and type policy combos
    SatInput("((Alice or Bob) or David)", "Bob", true),
    SatInput("((Alice and Bob) or David)", "Bob|David", true),
    SatInput("(Alice and (Bob or David))", "Bob|David", false),
    SatInput("(Alice and (Bob and David))", "Alice|Bob|David", true),
    SatInput("((Alice or Bob) and David)", "Bob|David", true),
    SatInput("((Alice or Bob) and David)", "Alice|Charlie", false),
    SatInput("((Alice or Bob) and David)", "Alice|David", true),
    SatInput("(David or Charlie)", "Alice|Bob", false),
    SatInput("Bar", "Alice|Bob", false),
    SatInput("Alice", "Alice|Bob", true),
    SatInput("Foor", "Bar", false),
    // test uids
    SatInput("((Alice and Bob) or uid:567abcdef)", "uid:567abcdef|Bob", true),
    SatInput("((Alice or Bob) and uid:567abcdef)", "uid:567abcdef|Bob", true),
    // test integer range
    SatInput("(Floor in (2-5) and Alice)", "Alice|Floor=3", true),
    SatInput("(Floor in (2-5) and Alice)", "Alice|Floor=7", false),
    // test dates and date ranges
    SatInput("(David or Date = January 1-31, 2015)", "David|Bob", true),
    SatInput("(David or Date = January 1-31, 2015)", "Date=January 27, 2015|Bob", true),
    SatInput("(David or Date = January 1-31, 2015)", "Date=March 17, 2015|Bob", false),
    SatInput("Date > January 1, 1971", "Date = January 1, 2010", true),
    SatInput("Date >= January 1, 1971", "Date = January 1, 1971", true),
    SatInput("Date <= January 1, 1971", "Date = January 1, 1975", false),
    SatInput("Date < January 1, 1971", "Date = December 1, 2000", false)
));
#endif

int main(int argc, char **argv) {
    int rc;

    InitializeOpenABE();

    ::testing::InitGoogleTest(&argc, argv);
    rc = RUN_ALL_TESTS();

    ShutdownOpenABE();

    return rc;
}
