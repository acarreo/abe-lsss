/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.

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

string createAttribute(int i)
{
    stringstream ss;
    ss << "Attr" << i;
    return ss.str();
}

bool getOpenABEAttributeList(int max, vector<string> & attrList)
{
    if(max <= 0) { return false; }
    int start = 0;
    // reset
    attrList.clear();
    for(int i = start; i <= max; i++) {
        attrList.push_back(createAttribute(i));
    }
    return true;
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
string getOpenABEPolicyString(int max)
{
    string policystr;
    if(max >= 2) {
        policystr = "(" + createAttribute(0) + " and " + createAttribute(1) + ")";
    }
    else if(max == 1) {
        policystr = createAttribute(0);
    }

    for(int i = 2; i <= max; i++)
    {
        policystr = "(" + policystr + " and " + createAttribute(i) + ")";
    }

    return policystr;
}

bool runLSSSTest(string policy_str, string attr_list_str, bool verbose = false)
{
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
    cout << "Obtained " << shares.size() << " secret shares" << endl;

    OpenABELSSS recoveryLsss;

    // OpenABEAttributeList *attrList = new OpenABEAttributeList(S.size(), S);
    unique_ptr<OpenABEAttributeList> attrList = createAttributeList(attr_list_str);
    if(verbose) {
    	cout << "AttrList: " << attrList->toString() << endl;
    }
    if(recoveryLsss.recoverCoefficients(policy.get(), attrList.get()) == false)
        return false;
    OpenABELSSSRowMap coefficients = recoveryLsss.getRows();
    cout << "Recovered " << coefficients.size() << " coefficients." << endl;

    ZP recSecret = recoveryLsss.LSSStestSecretRecovery(coefficients,  shares);
    return secret == recSecret;
}


/* Note on CPA security tests:
 * Decryption returns OpenABE_NOERROR in either a successful or failed decryption attempt except
 * if an exception is triggered due to invalid inputs. This is by design.
 */

namespace {

class Input {
public:
    Input(OpenABE_SCHEME scheme, const string enc_input,
          const string key, bool expect_pass,
          bool verbose = false) {
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

class CCASecurityForKEMTest : public CPASecurityForSchemeTest {};
class CCASecurityForSchemeTest : public CPASecurityForSchemeTest {};

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
        cout << "Input Plaintext: " << plaintext.toHex() << endl;
    	cout << "Enc Input used: " << input.func_input << endl;
    	cout << "Key Input used: " << input.key_input << endl;
    	cout << "Rec Plaintext: " << plaintext1.toHex() << endl;
    	cout << "Test expected to pass: " << (input.expect_pass_ ? "true" : "false") << endl;
    }
}

#if 0
/* Unit test fixture for CCA KEM contexts */
TEST_P(CCASecurityForKEMTest, testWorkingExamples) {
    Input input = GetParam();
    TEST_DESCRIPTION("Testing CCA-secure KEM " + printScheme(input.scheme_type) + " scheme with Key: '" + \
    		input.key_input + "' and Enc: '" + input.func_input + "'");

    OpenABECiphertext ciphertext1, ciphertext2;
    shared_ptr<OpenABESymKey> sym_key(new OpenABESymKey), sym_key1(new OpenABESymKey);
    // , sym_key2(new OpenABESymKey), sym_key3(new OpenABESymKey);

    cout << "* Testing CCA KEM security for " << printScheme(input.scheme_type) << " schemes..." << endl;
    unique_ptr<OpenABEContextCCA> ccaKEMContext = OpenABE_createABEContextForKEM(input.scheme_type);

    // Generate a set of parameters for an ABE authority
    ASSERT_TRUE(ccaKEMContext->generateParams(MPK, MSK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->exportKey(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->exportKey(MSK, mskBlob) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaKEMContext->deleteKey(MPK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->deleteKey(MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaKEMContext->loadMasterPublicParams(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->loadMasterSecretParams(MSK, mskBlob) == OpenABE_NOERROR);

    // encrypt under the specified functional input
    unique_ptr<OpenABEFunctionInput> encInput = getEncInput(input.scheme_type, input.func_input);
    // Encrypt a test key using the KEM mode
    ASSERT_TRUE(ccaKEMContext->encryptKEM(MPK, encInput.get(), DEFAULT_SYM_KEY_BYTES, sym_key, ciphertext1) == OpenABE_NOERROR);

    // make sure ABE ciphertext and header serialization works correctly
    ciphertext1.exportToBytes(ctBlob);
    ciphertext2.loadFromBytes(ctBlob);
    ASSERT_TRUE(ciphertext1 == ciphertext2);
    // verify header is thesame
    OpenABEByteString hdr1, hdr2;
    ciphertext1.getHeader(hdr1);
    ciphertext2.getHeader(hdr2);
    ASSERT_TRUE(hdr1 == hdr2);

    // for auth1 and auth2
    unique_ptr<OpenABEFunctionInput> keyInput = getKeyInput(input.scheme_type, input.key_input);

    ASSERT_TRUE(ccaKEMContext->generateDecryptionKey((OpenABEFunctionInput *)keyInput.get(), "GoodDecKey1", MPK, MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaKEMContext->exportKey("GoodDecKey1", skBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->deleteKey("GoodDecKey1") == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->loadUserSecretParams("GoodDecKey1", skBlob) == OpenABE_NOERROR);

    if (input.verbose_) {
    	cout << "Enc Input used: " << input.func_input << endl;
    	cout << "Key Input used: " << input.key_input << endl;
    	cout << "Test expected to pass: " << (input.expect_pass_ ? "true" : "false") << endl;
    }

    if (input.expect_pass_) {
        ASSERT_TRUE(ccaKEMContext->decryptKEM(MPK, "GoodDecKey1", ciphertext1, DEFAULT_SYM_KEY_BYTES, sym_key1) == OpenABE_NOERROR);
        ASSERT_TRUE(*sym_key == *sym_key1);
    } else {
        ASSERT_FALSE(ccaKEMContext->decryptKEM(MPK, "GoodDecKey1", ciphertext1, DEFAULT_SYM_KEY_BYTES, sym_key1) == OpenABE_NOERROR);
        ASSERT_FALSE(*sym_key == *sym_key1);
    }
}


/* Unit test fixture for CCA scheme contexts */
TEST_P(CCASecurityForSchemeTest, testWorkingExamples) {
    Input input = GetParam();
    TEST_DESCRIPTION("Testing CCA-secure scheme " + printScheme(input.scheme_type) + " scheme with Key: '" + \
    		input.key_input + "' and Enc: '" + input.func_input + "'");
    OpenABECiphertext ciphertext1, ciphertext_1, ciphertext2, ciphertext_2;

    cout << "* Testing CCA security for " << printScheme(input.scheme_type) << " schemes..." << endl;
    unique_ptr<OpenABEContextSchemeCCA> ccaSchemeContext = OpenABE_createContextABESchemeCCA(input.scheme_type);

    // Generate a set of parameters for an ABE authority
    ASSERT_TRUE(ccaSchemeContext->generateParams(MPK, MSK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->exportKey(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->exportKey(MSK, mskBlob) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaSchemeContext->deleteKey(MPK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->deleteKey(MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaSchemeContext->loadMasterPublicParams(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->loadMasterSecretParams(MSK, mskBlob) == OpenABE_NOERROR);

    // encrypt under the specified functional input
    unique_ptr<OpenABEFunctionInput> encInput = getEncInput(input.scheme_type, input.func_input);
    string pt = plaintext.toString();
    ASSERT_TRUE(ccaSchemeContext->encrypt(MPK, encInput.get(), pt, ciphertext_1, ciphertext_2) == OpenABE_NOERROR);

    // make sure ABE ciphertext and header serialization works correctly
    ciphertext_1.exportToBytes(ctBlob);
    ciphertext1.loadFromBytes(ctBlob);
    ASSERT_TRUE(ciphertext1 == ciphertext_1);
    // verify header is thesame
    OpenABEByteString hdr1, hdr2;
    ciphertext_1.getHeader(hdr1);
    ciphertext1.getHeader(hdr2);
    ASSERT_TRUE(hdr1 == hdr2);

    // make sure symmetric ciphertext serialization works correctly
    OpenABEByteString ctBlob1, ctBlob2;
    ciphertext_2.exportToBytesWithoutHeader(ctBlob1);
    ciphertext2.loadFromBytesWithoutHeader(ctBlob1);
    ciphertext2.exportToBytesWithoutHeader(ctBlob2);
    ASSERT_TRUE(ctBlob1 == ctBlob2);

    // for auth1 and auth2
    unique_ptr<OpenABEFunctionInput> keyInput = getKeyInput(input.scheme_type, input.key_input);

    ASSERT_TRUE(ccaSchemeContext->keygen((OpenABEFunctionInput *)keyInput.get(), "GoodDecKey1", MPK, MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaSchemeContext->exportKey("GoodDecKey1", skBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->deleteKey("GoodDecKey1") == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->loadUserSecretParams("GoodDecKey1", skBlob) == OpenABE_NOERROR);

    string pt1;
    if (input.expect_pass_) {
        ASSERT_TRUE(ccaSchemeContext->decrypt(MPK, "GoodDecKey1", pt1, ciphertext_1, ciphertext_2) == OpenABE_NOERROR);
        plaintext1 += pt1;
        ASSERT_TRUE(plaintext == plaintext1);
    } else {
        ASSERT_FALSE(ccaSchemeContext->decrypt(MPK, "GoodDecKey1", pt1, ciphertext_1, ciphertext_2) == OpenABE_NOERROR);
    }
}
#endif // CCASecurityForKEMTest

}

INSTANTIATE_TEST_CASE_P(ABETest1, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Alice|Charlie", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|David", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest2, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "uid:567abc", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Alice|Bob", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest3, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "Alice and Date = May 1-10, 2016", "Alice|Date=May 5, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "Date = May 1-10, 2016 and (Alice or Bob)", "Bob|Date=May 8, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and Date = May 1-10, 2016)", "Bob|Eve|Date=May 12, 2016", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Charlie|Date = June 12, 2014", "(Date = June 10-20, 2014 and (Charlie or David))", true),
    Input(OpenABE_SCHEME_KP_GPSW, "David|Date = June 25, 2014", "((David or Bob) and Date = June 21-28, 2014)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|Date = June 30, 2014", "((Alice and Date = June 21-28, 2014) and Charlie)", false)
));

#if 0
INSTANTIATE_TEST_CASE_P(ABETest4, CCASecurityForKEMTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Alice|Charlie", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|David", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|Eve", false)
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and Alice)", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest5, CCASecurityForKEMTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "uid:567abc", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Alice|Bob", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Bob|Eve", false)
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and Alice)", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest6, CCASecurityForKEMTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "Alice and Date = May 1-10, 2016", "Alice|Date=May 5, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "Date = May 1-10, 2016 and (Alice or Bob)", "Bob|Date=May 8, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and Date = May 1-10, 2016)", "Bob|Eve|Date=May 12, 2016", false)
    // Input(OpenABE_SCHEME_KP_GPSW, "Charlie|Date = June 12, 2014", "(Date = June 10-20, 2014 and (Charlie or David))", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "David|Date = June 25, 2014", "((David or Bob) and Date = June 21-28, 2014)", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|Date = June 30, 2014", "((Alice and Date = June 21-28, 2014) and Charlie)", false)
));


INSTANTIATE_TEST_CASE_P(ABETest7, CCASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Alice|Charlie", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|David", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|Eve", false)
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and Alice)", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest8, CCASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "uid:567abc", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Alice|Bob", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Bob|Eve", false)
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and Alice)", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest9, CCASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "Alice and Date = May 1-10, 2016", "Alice|Date=May 5, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "Date = May 1-10, 2016 and (Alice or Bob)", "Bob|Date=May 8, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and Date = May 1-10, 2016)", "Bob|Eve|Date=May 12, 2016", false)
    // Input(OpenABE_SCHEME_KP_GPSW, "Charlie|Date = June 12, 2014", "(Date = June 10-20, 2014 and (Charlie or David))", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "David|Date = June 25, 2014", "((David or Bob) and Date = June 21-28, 2014)", true),
    // Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|Date = June 30, 2014", "((Alice and Date = June 21-28, 2014) and Charlie)", false)
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
