#include <iostream>
#include <string>
#include <iomanip>

#include <lsss/zlsss.h>


using namespace std;

vector<string> policies = {
  "Level > 2 and Level < 35",
  "Day > 5 and Charlie",
  "(Day < 25) and (Floor == 3)",
  "(Date < January 1, 2017 and Bob)",
  "Levele > 2 and Levele < 35",
  "(Floor in (2-5) and Alice)",
  "((Date = December 10-16, 2023) and Charlie)"
};

int main(int argc, char const *argv[])
{
  if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK) {
    std::cout << "Failed to initialize libraries" << std::endl;
    return 1;
  }

  string policy = "(((Bob or Alice) and (Level > 3)) and Date = May 1-10, 2022)";
  string attributes = "Bob|Eve|uid:56ab7c|Date=May 2, 2022";

  string policy_hashed = hashPolicy(policy);
  string attributes_hashed = hashAttributesList(attributes);

  cout << "Policy hashed: " << policy_hashed << endl;
  cout << "Attributes hashed: " << attributes_hashed << endl;

  auto policy_tree_hashed = createPolicyTree(policy_hashed);
  auto attr_list_hashed = createAttributeList(attributes_hashed);

  cout << "Policy tree: " << policy_tree_hashed->toString() << endl;
  cout << "Attribute list: " << attr_list_hashed->toString() << endl;

  if (!policy_tree_hashed || !attr_list_hashed) {
    cout << "Failed to create policy tree or attribute list" << endl;
    return 2;
  }

  OpenABELSSS lsss;
  if (!lsss.recoverCoefficients(policy_tree_hashed.get(), attr_list_hashed.get())) {
    cout << "Failed to recover coefficients" << endl;
    return 3;
  }
  cout << "Policy with hash ---> satisfied" << endl;

  core_clean();
  return 0;
}
