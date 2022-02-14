#include <omp.h>
#include "AES128.hpp"


extern const std::vector<unsigned char> ECB_block;


class ECB {
public:
    static std::vector<std::vector<unsigned char>> encrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule);
    static std::vector<std::vector<unsigned char>> decrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule);
};