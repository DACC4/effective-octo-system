#include <iostream>
#include <sodium.h>

int main()
{
    if (sodium_init() < 0) {
        std::cout << "sodium_init() failed" << std::endl;
        return 1;
    }

    std::cout << "Hello, World!" << std::endl;

    return 0;
}
