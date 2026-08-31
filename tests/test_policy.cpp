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

string createAttribute(int i) {
  stringstream ss;
  ss << "Attr" << i;
  return ss.str();
}

bool getOpenABEAttributeList(int max, vector<string> & attrList) {
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
string getOpenABEPolicyString(int max) {
  string policystr;
  if(max >= 2) {
    policystr = "(" + createAttribute(0) + " and " + createAttribute(1) + ")";
  }
  else if(max == 1) {
    policystr = createAttribute(0);
  }

  for(int i = 2; i <= max; i++) {
    policystr = "(" + policystr + " and " + createAttribute(i) + ")";
  }

  return policystr;
}

bool runLSSSTest(string policy_str, string attr_list_str, bool verbose = false) {
  // Create a pairing object
  OpenABEPairing pairing;

  unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str);
  if(policy == nullptr) {
    throw runtime_error("Failed to parse policy: " + policy_str);
  }
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
  if(attrList == nullptr) {
    throw runtime_error("Failed to parse attribute list: " + attr_list_str);
  }
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


TEST(Attribute, SerializeAndDeserialize) {
  TEST_DESCRIPTION("Testing serialize and deserialize for attribute lists");
  OpenABEAttributeList attr_list;
  attr_list.addAttribute("Alice");
  attr_list.addAttribute("Bob");

  OpenABEByteString bytes;
  attr_list.serialize(bytes);
  OpenABEAttributeList attr_list2;
  attr_list2.deserialize(bytes);

  ASSERT_TRUE(attr_list.isEqual(&attr_list2));
}

class PolicyParser : public ::testing::Test {
  protected:
    virtual void SetUp() { }
};

TEST_F(PolicyParser, OrderOfParanthesis) {
  TEST_DESCRIPTION("Testing that basic ordering of parenthesis does not matter");
  unique_ptr<OpenABEPolicy> s1 = createPolicyTree("(one or two) and three");
  unique_ptr<OpenABEPolicy> s2 = createPolicyTree("three and (one or two)");
  ASSERT_TRUE(s1 != nullptr);
  ASSERT_TRUE(s2 != nullptr);
  set<string> attr_set1 = s1->getAttrCompleteSet();
  set<string> attr_set2 = s2->getAttrCompleteSet();
  ASSERT_EQ(attr_set1, attr_set2);
}

TEST_F(PolicyParser, DateRangePolicy) {
  TEST_DESCRIPTION("Testing that we can handle range of dates policies");
  ASSERT_TRUE(createPolicyTree("Date = January 1-31, 2016") != nullptr);
  ASSERT_TRUE(createPolicyTree("Date = February 1-15, 2016") != nullptr);
  ASSERT_TRUE(createPolicyTree("Date = March 21-28, 2016") != nullptr);
}

TEST_F(PolicyParser, ValidDatePolicy) {
  TEST_DESCRIPTION("Testing that we can handle date type policies");
  ASSERT_TRUE(createPolicyTree("Date = January 5, 2016") != nullptr);
  ASSERT_TRUE(createPolicyTree("Date > January 5, 2016") != nullptr);
  ASSERT_TRUE(createPolicyTree("Date < January 5, 2016") != nullptr);
  ASSERT_TRUE(createPolicyTree("Date <= January 5, 2016") != nullptr);
  ASSERT_TRUE(createPolicyTree("Date >= January 5, 2016") != nullptr);
}

TEST_F(PolicyParser, InvalidDate) {
  TEST_DESCRIPTION("Testing that an exception is thrown for invalid dates before unix epoch");
  ASSERT_FALSE(createPolicyTree("Date = January 1, 1968"));
}

TEST_F(PolicyParser, InvalidStartDateRange) {
  TEST_DESCRIPTION("Testing that an exception is thrown for an invalid date range");
  ASSERT_FALSE(createPolicyTree("Date = January 0-10, 1970"));
}


TEST_F(PolicyParser, InvalidEndDateRange) {
  TEST_DESCRIPTION("Testing that an exception is thrown for an invalid date range");
  ASSERT_FALSE(createPolicyTree("Date = January 1-40, 1970"));
}

TEST_F(PolicyParser, InvalidDateFormat) {
  TEST_DESCRIPTION("Testing that dates are specified correctly");
  ASSERT_FALSE(createPolicyTree("(One or Two) and (Date : January 1, 1970)"));
}

TEST_F(PolicyParser, IntegerRangePolicy) {
  TEST_DESCRIPTION("Testing that range of integers supported in the policy");
  ASSERT_TRUE(createPolicyTree("Level in (2-35)"));
  unique_ptr<OpenABEPolicy> s1 = createPolicyTree("Level > 2 and Level < 35");
  ASSERT_TRUE(s1 != nullptr);
}

TEST_F(PolicyParser, InvalidExpInts) {
  // verifying invalid policies are caught appropriately
  TEST_DESCRIPTION("Testing that integers in expint can be represented by number of bits specified");
  // make sure integers in expint can be represented by number of bits specified
  ASSERT_FALSE(createPolicyTree("Month < 16#4"));
}

TEST_F(PolicyParser, InvalidExpIntsWithZero) {
  TEST_DESCRIPTION("Testing that integers in expint can be represented by number of bits specified");
  // make sure integers in expint can be represented by number of bits specified
  ASSERT_FALSE(createPolicyTree("Month < 4#0"));
}

TEST_F(PolicyParser, NegativeIntegerInPolicies) {
  TEST_DESCRIPTION("Testing that negative integers are not allowed");
  // make sure negative integers are not allowed
  ASSERT_FALSE(createPolicyTree("Month > -1#4"));
  ASSERT_FALSE(createPolicyTree("Month < -3#4"));
}

TEST_F(PolicyParser, LessThanGreaterThanNotInAttributeList) {
  TEST_DESCRIPTION("Testing that >,<=,etc cannot be added in attribute lists");
  // make sure we can't add >,<=,etc in attribute lists
  ASSERT_FALSE(createAttributeList("Alice|Day >= 100|Bob"));
}

TEST_F(PolicyParser, ExpIntForAttributeList) {
  TEST_DESCRIPTION("Testing that expint logic applies to attribute lists");
  // make sure expint logic applies to attribute lists as well. striving for uniformity
  ASSERT_FALSE(createAttributeList("Alice|Day = 1000#8|Bob"));
}

TEST_F(PolicyParser, DuplicateDatesInAttributeListAreIgnored) {
  TEST_DESCRIPTION("Testing that duplicate dates in attribute lists are ignored");
  string a = "|Date = May 10, 2017|Alice";
  unique_ptr<OpenABEAttributeList> attr_list1 = createAttributeList(a + "|Date = July 1, 2015");
  unique_ptr<OpenABEAttributeList> attr_list2 = createAttributeList(a);
  string a1 = attr_list1->toString();
  string a2 = attr_list2->toString();
  ASSERT_TRUE(a1.compare(a2) == 0);
}

TEST_F(PolicyParser, ExpIntNotAllowedInInputAttribute) {
  TEST_DESCRIPTION("Testing that user cannot specify expint as part of an attribute list");
  // make sure user cannot specify expint as part of an attribute
  ASSERT_FALSE(createAttributeList("foo_expint04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx|bar"));
}

TEST_F(PolicyParser, ExpIntNotAllowedInInputPolicy) {
  TEST_DESCRIPTION("Testing that user cannot specify expint as part of a policy");
  ASSERT_FALSE(createPolicyTree("Alice or foo_expint04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx"));
}

class LinearSecretSharing : public ::testing::Test {
  protected:
    virtual void SetUp() {
      verbose = false;
  }
  bool verbose;
};

TEST_F(LinearSecretSharing, TestWithGreaterThan) {
  TEST_DESCRIPTION("Testing LSSS with greater than type policy");
  ASSERT_TRUE(runLSSSTest("Day > 5 and Charlie", "Charlie|Day=7", verbose));
}

TEST_F(LinearSecretSharing, TestWithGreaterThanOrEqual) {
  TEST_DESCRIPTION("Testing LSSS with greater than or equal type policy");
  string attrList = "Day = 7";
  ASSERT_TRUE(runLSSSTest("(Day >= 5)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Day >= 12)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithLessThan) {
  TEST_DESCRIPTION("Testing LSSS with less than operation");
  string attrList = "Day = 17";
  ASSERT_TRUE(runLSSSTest("(Day < 25)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Day < 5)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithLessThanOrEqual) {
  TEST_DESCRIPTION("Testing LSSS with less than or equal type policy");
  string attrList = "Day = 7000";
  ASSERT_TRUE(runLSSSTest("(Day <= 7000)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Day <= 5)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithEquality) {
  TEST_DESCRIPTION("Testing LSSS with just equality type policy");
  string attrList = "Month = 7#4";
  ASSERT_TRUE(runLSSSTest("(Month == 7#4)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Month == 6#4)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestOtherComparisonOps) {
  TEST_DESCRIPTION("Testing LSSS with multiple comparison ops in addition to other attributes in the policy");
  string attrList = "Month = 7#4|Bob|Charlie";
  ASSERT_TRUE(runLSSSTest("(Month<12#4 and Bob)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("(Month> 2#4 and Charlie)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("(Month <10#4 and Charlie)", attrList, verbose));
  // make sure this throws an exception. '==' required for equality testing
  ASSERT_ANY_THROW(runLSSSTest("(Month= 2#4 and Charlie)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithSimpleDatePolicies) {
  TEST_DESCRIPTION("Testing LSSS with simple date type policies");
  string attrList = "|Date = December 15, 2015|Bob|Charlie";
  ASSERT_TRUE(runLSSSTest("(Date < January 1, 2017 and Bob)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Date > March 10, 2016 and Charlie)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithIntegerRangeTypePolicies) {
  TEST_DESCRIPTION("Testing LSSS with integer range type policies");
  string attrList = "|Bob|Month = 7#4";
  ASSERT_TRUE(runLSSSTest("(Month in (3#4-15#4) and Bob)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Month in (3#4-5#4) and Bob)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithDateRangeTypePolicies) {
  TEST_DESCRIPTION("Testing LSSS with date range type policies");
  string attrList = "|Date = December 15, 2016|Charlie";
  ASSERT_TRUE(runLSSSTest("((Date = December 10-16, 2016) and Charlie)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("((Date = December 1-14, 2016) and Charlie)", attrList, verbose));
}

TEST(LSSS, TestCorrectnessOfOrPolicyTree) {
  TEST_DESCRIPTION("Testing correctness of different policy trees");
  // Create attribute list
  string attrList = "|Alice|Bob|Charlie|David";
  bool verbose = true;
  ASSERT_TRUE(runLSSSTest("(Alice or Bob)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("(Alice and Bob)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("(Eve or Alice)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Eve or Frank) and Alice", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("((Alice or Bob) and Charlie)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("((Alice or Bob) and (Charlie or David))", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("((Alice and Bob) or (Charlie and David))", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Alice and (Eve or Frank))", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("(Alice or (Eve and Frank))", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("((Eve and Frank) or Alice)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("(Alice or (Eve or Frank))", attrList, verbose));
  // here we are selecting the shortest path to satisfy the tree (exercising sort logic)
  ASSERT_TRUE(runLSSSTest("((Bob and Charlie) or Alice)", attrList, verbose));
  ASSERT_FALSE(runLSSSTest("(Alice and Eve)", attrList, verbose));
  // test ability to sort
  cout << "* Test ability to sort..." << endl;
  ASSERT_TRUE(runLSSSTest("(Alice or (Bob and Charlie))", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("((Bob and Charlie) or Alice)", attrList, verbose));
}

TEST(LSSS, TestCorrectnessWithDupAttributes) {
  TEST_DESCRIPTION("Testing correctness when duplicate attributes are present");
  string attrList = "|Alice|Bob|Charlie|David";
  bool verbose = true;
  ASSERT_TRUE(runLSSSTest("(Alice or Alice)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("(Alice and Alice)", attrList, verbose));
  ASSERT_TRUE(runLSSSTest("((Alice and Alice) and Bob)", attrList, verbose));
}

string convertToAttributeListString(vector<string>& attr_list) {
  string a_str = "|";
  for (auto a : attr_list) {
    a_str += a + "|";
  }
  return a_str;
}

TEST(LSSS, TestCorrectnessOfBalancedAndPolicyTree) {
  TEST_DESCRIPTION("Testing correctness of balanced policy trees");
  // get a comprehensive list of attributes
  string attr_list_good, attr_list_bad;
  vector<string> attrListGood, attrListBad;
  getOpenABEAttributeList(1024, attrListGood);
  attrListBad = attrListGood;
  attrListBad.erase(attrListBad.begin());

  int attrCount = 4;
  string balanced_policy_str = getBalancedOpenABETree(0, attrCount);
  // call function to convert attrListGood to a string sep by '|'
  attr_list_good = convertToAttributeListString(attrListGood);
  ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));

  attrCount = 1024;
  balanced_policy_str = getBalancedOpenABETree(0, attrCount);
  attr_list_bad = convertToAttributeListString(attrListBad);
  ASSERT_FALSE(runLSSSTest(balanced_policy_str, attr_list_bad));

  // attrCount = 16384;
  // balanced_policy_str = getBalancedOpenABETree(0, attrCount);
  // ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));

  // attrCount = 32768;
  // balanced_policy_str = getBalancedOpenABETree(0, attrCount);
  // ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));

  // takes a few minutes to test
  // attrCount = 65536;
  // balanced_policy_str = getBalancedOpenABETree(0, attrCount);
  // getOpenABEAttributeList(attrCount, attrListGood);
  // attr_list_good = convertToAttributeListString(attrListGood);
  // ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));
}

TEST(LSSS, TestCorrectnessOfSkewedAndPolicyTree) {
  TEST_DESCRIPTION("Testing correctness of LSSS on a skewed policy tree");

  string attr_list_good, attr_list_bad;
  // get a comprehensive list of attributes
  vector<string> attrListGood, attrListBad;
  getOpenABEAttributeList(1024, attrListGood);
  attrListBad = attrListGood;
  attrListBad.erase(attrListBad.begin());

  int attrCount = 4;
  string skewed_policy_str = getOpenABEPolicyString(attrCount-1);
  attr_list_good = convertToAttributeListString(attrListGood);
  ASSERT_TRUE(runLSSSTest(skewed_policy_str, attr_list_good));

  attrCount = 1024;
  skewed_policy_str = getOpenABEPolicyString(attrCount-1);
  attr_list_bad = convertToAttributeListString(attrListBad);
  ASSERT_TRUE(runLSSSTest(skewed_policy_str, attr_list_good));
  ASSERT_FALSE(runLSSSTest(skewed_policy_str, attr_list_bad));

  // attrCount = 16384;
  // getOpenABEAttributeList(attrCount, attrListGood);
  // skewed_policy_str = getOpenABEPolicyString(attrCount-1);
  // attr_list_good = convertToAttributeListString(attrListGood);
  // ASSERT_TRUE(runLSSSTest(skewed_policy_str, attr_list_good));

  // might take a few minutes to test
  // attrCount = 32768;
  // getOpenABEAttributeList(attrCount, attrListGood);
  // attr_list_good = convertToAttributeListString(attrListGood);
  // skewed_policy_str = getOpenABEPolicyString(attrCount-1);
  // ASSERT_TRUE(runLSSSTest(skewed_policy_str, attr_list_good));

  // takes a few minutes to test
  // attrCount = 65536;
  // getOpenABEAttributeList(attrCount, attrListGood);
  // attr_list_good = convertToAttributeListString(attrListGood);
  // string balanced_policy_str = getBalancedOpenABETree(0, attrCount);
  // ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));
}


class SatInput {
  public:
    SatInput(const string policy_str, const string attr_list, bool expect_pass) {
    	policy_str_ = policy_str;
    	attr_list_ = attr_list;
      expect_pass_ = expect_pass;
      verbose_ = false;
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


int main(int argc, char **argv) {
  int rc;

  InitializeOpenABE();

  ::testing::InitGoogleTest(&argc, argv);
  rc = RUN_ALL_TESTS();

  ShutdownOpenABE();

  return rc;
}
