#include <iostream>

#include <abe_lsss/abe/zabe.h>
#include <abe_lsss/lsss/zlsss.h>

using namespace std;

int main(int argc, char const *argv[])
{
    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK) {
        cerr << "Failed to initialize libraries" << endl;
        return 1;
    }

    // Generate a prime number of n_bits
    cout << "The prime number P in decimal is:" << endl;
    ZP prime;
    uint16_t n_bits = 32;

    prime.setPrime(n_bits);
    cout << prime << endl << endl;

    // Choose random alpha modulo P, which is an element of prime field
    cout << "Generate alpha modulo the 'prime' P" << endl;

    ZP alpha;
    alpha.setRandom(prime);
    cout << alpha << endl << endl;

    // cout << "Print in hexadecimal:" << endl;
    // cout << prime.getBytesAsString() << endl << endl;
    // cout << alpha.getBytesAsString() << endl;

    return 0;
}
