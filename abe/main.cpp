#include <lsss_abe.h>

using namespace std;

int main(int argc, char const *argv[])
{
    InitializeOpenABE();

    cout << "Hello... je suis content." << endl;

    ShutdownOpenABE();
    return 0;
}
