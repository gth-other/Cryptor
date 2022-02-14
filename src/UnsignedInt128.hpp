#include <iostream>
#include <vector>
#include <random>


class UnsignedInt128 {
public:
    UnsignedInt128();
    UnsignedInt128(std::vector<unsigned char> block);
    static UnsignedInt128 random();
    friend UnsignedInt128 operator +(UnsignedInt128 number_first, unsigned long long number_second);
    static std::vector<unsigned char> to_block(UnsignedInt128 number);
private:
    std::vector<unsigned long long> _digits;
};