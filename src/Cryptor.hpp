#include <fstream>
#include "CTR.hpp"
#include "SHA256.hpp"


class Cryptor {
public:
    static void init_multithreading(int threads_number);
    static std::vector<unsigned char> generate_key_from_password(std::vector<unsigned char> password, int iterations);
    static void encrypt_file(const std::string& file_input_location, const std::string& file_output_location, const std::string& mode, const std::vector<unsigned char>& key, std::vector<std::vector<unsigned char>> key_schedule);
    static void decrypt_file(const std::string& file_input_location, const std::string& file_output_location, const std::vector<unsigned char>& key, std::vector<std::vector<unsigned char>> key_schedule);
private:
    static std::vector<std::vector<unsigned char>> _add_file_data(std::vector<std::vector<unsigned char>> blocks, const std::string& file_location);
    static std::vector<std::vector<unsigned char>> _edit_incomplete_block(std::vector<std::vector<unsigned char>> blocks);
    static std::vector<std::vector<unsigned char>> _add_key_hash(std::vector<std::vector<unsigned char>> blocks, std::vector<unsigned char> key);
    static void _write(std::vector<std::vector<unsigned char>> blocks, const std::string& file_location);
    static std::vector<std::vector<unsigned char>> _get_data_and_check_size(const std::string& file_location);
    static std::vector<std::vector<unsigned char>> _check_and_delete_key_hash(std::vector<std::vector<unsigned char>> blocks, std::vector<unsigned char> key);
    static std::vector<std::vector<unsigned char>> _edit_supplemented_block(std::vector<std::vector<unsigned char>> blocks);
};