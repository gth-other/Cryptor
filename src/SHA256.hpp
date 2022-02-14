#include <iostream>
#include <array>
#include <vector>
#include <cstring>


class SHA256 {
public:
    static std::vector<unsigned char> get_hash(std::vector<unsigned char> message);
private:
    static unsigned int _rotr(unsigned int number_first, unsigned int number_second);
    static unsigned int _convert_word_to_unsigned_int(std::vector<unsigned char> word);
};