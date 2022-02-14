#include "ECB.hpp"
#include "UnsignedInt128.hpp"


extern const std::vector<unsigned char> CTR_block;


class CTR {
public:
    static std::vector<std::vector<unsigned char>> encrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule);
    static std::vector<std::vector<unsigned char>> decrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule);
};