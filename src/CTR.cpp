#include "CTR.hpp"


const std::vector<unsigned char> CTR_block = {'C', 'T', 'R', 0x00,
                                              0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00};
std::vector<std::vector<unsigned char>> CTR::encrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule) {
    UnsignedInt128 counter = UnsignedInt128::random();
#pragma omp parallel for
    for (unsigned long long i = 0; i < blocks.size(); i = i + 1) {
        blocks[i] = AES128::_add_round_key(blocks[i], AES128::encrypt_block(UnsignedInt128::to_block(counter + i), key, key_schedule));
    }
    blocks.push_back(CTR_block);
    blocks.push_back(UnsignedInt128::to_block(counter));
    return blocks;
}
std::vector<std::vector<unsigned char>> CTR::decrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule) {
    UnsignedInt128 counter = blocks[blocks.size() - 1];
    blocks.pop_back();
    blocks.pop_back();
#pragma omp parallel for
    for (unsigned long long i = 0; i < blocks.size(); i = i + 1) {
        blocks[i] = AES128::_add_round_key(blocks[i], AES128::encrypt_block(UnsignedInt128::to_block(counter + i), key, key_schedule));
    }
    return blocks;
}