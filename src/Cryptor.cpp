#include "Cryptor.hpp"


static const std::string ECB_mode = "ECB_mode";
static const std::string CTR_mode = "CTR_mode";
static const std::vector<unsigned char> block_for_addition = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};
void Cryptor::init_multithreading(int threads_number) {
    omp_set_num_threads(threads_number);
}
std::vector<unsigned char> Cryptor::generate_key_from_password(std::vector<unsigned char> password, int iterations) {
    if (iterations < 1000 or iterations > 130000) {
        throw "Fatal error. Unsafe number of iterations.";
    }
    if (password.size() < 8) {
        throw "Fatal error. Weak password.";
    }
    std::vector<unsigned char> hash = SHA256::get_hash(std::move(password));
    for (int i = 0; i < iterations - 1; i = i + 1) {
        hash = SHA256::get_hash(hash);
    }
    hash.resize(16);
    return hash;
}
void Cryptor::encrypt_file(const std::string& file_input_location, const std::string& file_output_location, const std::string& mode, const std::vector<unsigned char>& key, std::vector <std::vector<unsigned char>> key_schedule) {
    if (key.size() != 16) {
        throw "Fatal error. Invalid key size";
    }
    if (key_schedule.size() != 10) {
        throw "Fatal error. Invalid key schedule.";
    }
    for (int i = 0; i < 10; i = i + 1) {
        if (key_schedule[i].size() != 16) {
            throw "Fatal error. Invalid key schedule.";
        }
    }
    if (mode != ECB_mode and mode != CTR_mode) {
        throw "Fatal error. Unknown mode.";
    }
    std::vector<std::vector<unsigned char>> blocks;
    blocks = Cryptor::_add_file_data(blocks, file_input_location);
    blocks = Cryptor::_edit_incomplete_block(blocks);
    if (mode == ECB_mode) {
        blocks = ECB::encrypt_blocks(blocks, key, key_schedule);
    }
    else {
        blocks = CTR::encrypt_blocks(blocks, key, key_schedule);
    }
    blocks = Cryptor::_add_key_hash(blocks, key);
    Cryptor::_write(blocks, file_output_location);
}
void Cryptor::decrypt_file(const std::string& file_input_location, const std::string& file_output_location, const std::vector<unsigned char>& key, std::vector <std::vector<unsigned char>> key_schedule) {
    if (key.size() != 16) {
        throw "Fatal error. Invalid key size";
    }
    if (key_schedule.size() != 10) {
        throw "Fatal error. Invalid key schedule.";
    }
    for (int i = 0; i < 10; i = i + 1) {
        if (key_schedule[i].size() != 16) {
            throw "Fatal error. Invalid key schedule.";
        }
    }
    std::vector<std::vector<unsigned char>> blocks = Cryptor::_get_data_and_check_size(file_input_location);
    blocks = Cryptor::_check_and_delete_key_hash(blocks, key);
    if (blocks[blocks.size() - 2] == ECB_block) {
        blocks = ECB::decrypt_blocks(blocks, key, key_schedule);
    }
    else if (blocks[blocks.size() - 2] == CTR_block) {
        blocks = CTR::decrypt_blocks(blocks, key, key_schedule);
    }
    else {
        throw "Fatal error. File has been corrupted.";
    }
    blocks = Cryptor::_edit_supplemented_block(blocks);
    Cryptor::_write(blocks, file_output_location);
}
std::vector<std::vector<unsigned char>> Cryptor::_add_file_data(std::vector<std::vector<unsigned char>> blocks, const std::string& file_location) {
    std::ifstream file(file_location, std::ios::binary);
    if (!file.is_open()) {
        throw "Fatal error. Invalid old file location";
    }
    std::vector<unsigned char> data(std::istreambuf_iterator<char>(file), {});
    file.close();
    blocks.reserve(data.size() / 16);
    std::vector<unsigned char> block(16);
    for (long long i = 0; i < data.size(); i = i + 16) {
        for (int j = 0; j < 16; j = j + 1) {
            if (i + j >= data.size()) {
                block.pop_back();
            }
            else {
                block[j] = data[i + j];
            }
        }
        blocks.push_back(block);
    }
    return blocks;
}
std::vector<std::vector<unsigned char>> Cryptor::_edit_incomplete_block(std::vector<std::vector<unsigned char>> blocks) {
    if (blocks[blocks.size() - 1].size() == 16) {
        blocks.push_back(block_for_addition);
    }
    else {
        blocks[blocks.size() - 1].reserve(16 - blocks[blocks.size() - 1].size());
        blocks[blocks.size() - 1].push_back(0x01);
        while (blocks[blocks.size() - 1].size() != 16) {
            blocks[blocks.size() - 1].push_back(0x00);
        }
    }
    return blocks;
}
std::vector<std::vector<unsigned char>> Cryptor::_add_key_hash(std::vector<std::vector<unsigned char>> blocks, std::vector<unsigned char> key) {
    std::vector<unsigned char> hash = SHA256::get_hash(std::move(key));
    blocks.resize(blocks.size() + 2);
    blocks[blocks.size() - 2].resize(16);
    blocks[blocks.size() - 1].resize(16);
    for (int i = 0; i < 32; i = i + 1) {
        blocks[blocks.size() - 2 + (i / 16)][i % 16] = hash[i];
    }
    return blocks;
}
void Cryptor::_write(std::vector<std::vector<unsigned char>> blocks, const std::string& file_location) {
    std::vector<unsigned char> data;
    for (long long i = 0; i < blocks.size(); i = i + 1) {
        data.reserve(16);
        std::move(blocks[i].begin(), blocks[i].end(), std::back_inserter(data));
    }
    std::ofstream file(file_location, std::ios::binary);
    if (!file.is_open()) {
        throw "Fatal error. Invalid new file location";
    }
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(file));
    file.close();
}
std::vector<std::vector<unsigned char>> Cryptor::_get_data_and_check_size(const std::string& file_location) {
    std::ifstream file(file_location, std::ios::binary);
    if (!file.is_open()) {
        throw "Fatal error. Invalid old file location";
    }
    std::vector<unsigned char> data(std::istreambuf_iterator<char>(file), {});
    file.close();
    if (data.size() < 64 or data.size() % 16 != 0) {
        throw "Fatal error. File has been corrupted.";
    }
    std::vector<std::vector<unsigned char>> blocks;
    blocks.reserve(data.size() / 16);
    std::vector<unsigned char> block(16);
    for (long long i = 0; i < data.size(); i = i + 16) {
        for (int j = 0; j < 16; j = j + 1) {
            if (i + j >= data.size()) {
                block.pop_back();
            }
            else {
                block[j] = data[i + j];
            }
        }
        blocks.push_back(block);
    }
    return blocks;
}
std::vector<std::vector<unsigned char>> Cryptor::_check_and_delete_key_hash(std::vector<std::vector<unsigned char>> blocks, std::vector<unsigned char> key) {
    std::vector<unsigned char> hash;
    hash.reserve(32);
    for (long long i = blocks.size() - 2; i < blocks.size(); i = i + 1) {
        for (int j = 0; j < 16; j = j + 1) {
            hash.push_back(blocks[i][j]);
        }
    }
    if (hash != SHA256::get_hash(std::move(key))) {
        throw "Fatal error. Invalid key or file has been corrupted.";
    }
    blocks.pop_back();
    blocks.pop_back();
    return blocks;
}
std::vector<std::vector<unsigned char>> Cryptor::_edit_supplemented_block(std::vector<std::vector<unsigned char>> blocks) {
    for (int i = blocks[blocks.size() - 1].size() - 1; i >= 0; i = i - 1) {
        if (blocks[blocks.size() - 1][blocks[blocks.size() - 1].size() - 1] == 0x01) {
            blocks[blocks.size() - 1].pop_back();
            return blocks;
        }
        blocks[blocks.size() - 1].pop_back();
    }
    throw "Fatal error. File has been corrupted.";
}