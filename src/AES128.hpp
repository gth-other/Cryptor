#include <iostream>
#include <array>
#include <vector>
#include <random>


class AES128 {
public:
    static std::vector<unsigned char> generate_random_key();
    static std::vector<std::vector<unsigned char>> key_expansion(std::vector<unsigned char> key_old);
    static std::vector<unsigned char> encrypt_block(std::vector<unsigned char> block, std::vector<unsigned char> key, std::vector<std::vector<unsigned char>> key_schedule);
    static std::vector<unsigned char> decrypt_block(std::vector<unsigned char> block, std::vector<unsigned char> key, std::vector<std::vector<unsigned char>> key_schedule);
    friend class CTR;
private:
    static std::vector<unsigned char> _sub_bytes(std::vector<unsigned char> block);
    static std::vector<unsigned char> _shift_rows(std::vector<unsigned char> block);
    static std::vector<unsigned char> _mix_columns(std::vector<unsigned char> block);
    static std::vector<unsigned char> _add_round_key(std::vector<unsigned char> block, std::vector<unsigned char> key);
    static std::vector<unsigned char> _inversion_sub_bytes(std::vector<unsigned char> block);
    static std::vector<unsigned char> _inversion_shift_rows(std::vector<unsigned char> block);
    static std::vector<unsigned char> _inversion_mix_columns(std::vector<unsigned char> block);
    static std::vector<unsigned char> _inversion_add_round_key(std::vector<unsigned char> block, std::vector<unsigned char> key);
};