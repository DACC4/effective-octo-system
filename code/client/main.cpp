#include <iostream>
#include <sodium.h>

int main()
{
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cout << "sodium_init() failed" << std::endl;
        return 1;
    }



    return 0;
}
