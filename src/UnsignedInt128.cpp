#include "UnsignedInt128.hpp"


UnsignedInt128::UnsignedInt128() {
    _digits.resize(16);
}
UnsignedInt128::UnsignedInt128(std::vector<unsigned char> block) {
    _digits.resize(16);
    for (int i = 0; i < 16; i = i + 1) {
        _digits[i] = block[i];
    }
}
UnsignedInt128 UnsignedInt128::random() {
    std::random_device random_device;
    std::mt19937 mersenne(random_device());
    UnsignedInt128 number;
    for (int i = 1; i < 16; i = i + 1) {
        number._digits[i] = mersenne() % 256;
    }
    return number;
}
UnsignedInt128 operator +(UnsignedInt128 number_first, unsigned long long number_second) {
    number_first._digits[15] = number_first._digits[15] + number_second;
    for (int i = 15; i >= 1; i = i - 1) {
        number_first._digits[i - 1] = number_first._digits[i - 1] + (number_first._digits[i] / 256);
        number_first._digits[i] = number_first._digits[i] % 256;
    }
    return number_first;
}
std::vector<unsigned char> UnsignedInt128::to_block(UnsignedInt128 number) {
    std::vector<unsigned char> block(16);
    for (int i = 0; i < 16; i = i + 1) {
        block[i] = (unsigned char)number._digits[i];
    }
    return block;
}