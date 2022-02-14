#include "ECB.hpp"


const std::vector<unsigned char> ECB_block = {'E', 'C', 'B', 0x00,
                                              0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x00, 0x00};
std::vector<std::vector<unsigned char>> ECB::encrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule) {
#pragma omp parallel for
    for (unsigned long long i = 0; i < blocks.size(); i = i + 1) {
        blocks[i] = AES128::encrypt_block(blocks[i], key, key_schedule);
    }
    blocks.push_back(ECB_block);
    blocks.push_back(ECB_block);
    return blocks;
}
std::vector<std::vector<unsigned char>> ECB::decrypt_blocks(std::vector<std::vector<unsigned char>> blocks, const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule) {
    blocks.pop_back();
    blocks.pop_back();
#pragma omp parallel for
    for (unsigned long long i = 0; i < blocks.size(); i = i + 1) {
        blocks[i] = AES128::decrypt_block(blocks[i], key, key_schedule);
    }
    return blocks;
}