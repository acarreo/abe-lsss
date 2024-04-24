#include <iostream>

#include <lsss_abe/abe/zabe.h>
#include <lsss_abe/lsss/zlsss.h>

using namespace std;

int main(int argc, char const *argv[])
{
    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK) {
        cerr << "Failed to initialize libraries" << endl;
        return 1;
    }

    cout << "Je suis content" << endl;

    return 0;
}
