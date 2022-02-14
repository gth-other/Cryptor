#include <iostream>
#include <vector>
#include <fstream>
#include <chrono>
#include "../src/Cryptor.hpp"


void ECB_test(const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule) {
    long double time_encryption_start = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    Cryptor::encrypt_file("../examples/tux_original.bmp", "../examples/ECB/tux_encrypted.encrypted", "ECB_mode", key, key_schedule);
    long double time_encryption_end = std::chrono::high_resolution_clock::now().time_since_epoch().count();


    long double time_decryption_start = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    Cryptor::decrypt_file("../examples/ECB/tux_encrypted.encrypted", "../examples/ECB/tux_decrypted.bmp", key, key_schedule);
    long double time_decryption_end = std::chrono::high_resolution_clock::now().time_since_epoch().count();


    std::ifstream file_first("../examples/tux_original.bmp");
    std::ifstream file_second("../examples/ECB/tux_decrypted.bmp");
    std::vector<unsigned char> data_first(std::istreambuf_iterator<char>(file_first), {});
    std::vector<unsigned char> data_second(std::istreambuf_iterator<char>(file_second), {});
    file_first.close();
    file_second.close();


    if (data_first == data_second) {
        std::cout << "Оригинальный и расшифрованный файлы совпадают." << std::endl;
        long double time_encryption = time_encryption_end - time_encryption_start;
        long double time_decryption = time_decryption_end - time_decryption_start;
        long double size = data_first.size();
        std::cout << "Скорость шифрования (с учетом затрат на чтение и запись на диск): " << size * 7629 / time_encryption << " Мб / сек." << std::endl;
        std::cout << "Скорость дешифрования (с учетом затрат на чтение и запись на диск): " << size * 7629 / time_decryption << " Мб / сек." << std::endl;
    }
    else {
        std::cout << "Оригинальный и расшифрованный файл не совпадают." << std::endl;
    }
}
void CTR_test(const std::vector<unsigned char>& key, const std::vector<std::vector<unsigned char>>& key_schedule) {
    long double time_encryption_start = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    Cryptor::encrypt_file("../examples/tux_original.bmp", "../examples/CTR/tux_encrypted.encrypted", "CTR_mode", key, key_schedule);
    long double time_encryption_end = std::chrono::high_resolution_clock::now().time_since_epoch().count();


    long double time_decryption_start = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    Cryptor::decrypt_file("../examples/CTR/tux_encrypted.encrypted", "../examples/CTR/tux_decrypted.bmp", key, key_schedule);
    long double time_decryption_end = std::chrono::high_resolution_clock::now().time_since_epoch().count();


    std::ifstream file_first("../examples/tux_original.bmp");
    std::ifstream file_second("../examples/CTR/tux_decrypted.bmp");
    std::vector<unsigned char> data_first(std::istreambuf_iterator<char>(file_first), {});
    std::vector<unsigned char> data_second(std::istreambuf_iterator<char>(file_second), {});
    file_first.close();
    file_second.close();


    if (data_first == data_second) {
        std::cout << "Оригинальный и расшифрованный файлы совпадают." << std::endl;
        long double time_encryption = time_encryption_end - time_encryption_start;
        long double time_decryption = time_decryption_end - time_decryption_start;
        long double size = data_first.size();
        std::cout << "Скорость шифрования (с учетом затрат на чтение и запись на диск): " << size * 7629 / time_encryption << " Мб / сек." << std::endl;
        std::cout << "Скорость дешифрования (с учетом затрат на чтение и запись на диск): " << size * 7629 / time_decryption << " Мб / сек." << std::endl;
    }
    else {
        std::cout << "Оригинальный и расшифрованный файл не совпадают." << std::endl;
    }
}
void SHA256_test() {
    std::ifstream file("../examples/tux_original.bmp");
    std::vector<unsigned char> data(std::istreambuf_iterator<char>(file), {});
    file.close();


    long double time_start = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::vector<unsigned char> hash = SHA256::get_hash(data);
    long double time_end = std::chrono::high_resolution_clock::now().time_since_epoch().count();


    if (hash == (std::vector<unsigned char>){0x17, 0x5, 0xd3, 0x30, 0xdb, 0x3f, 0xe0, 0xa0, 0xb2, 0xfb, 0x86, 0x69, 0xc0, 0x16, 0xec, 0x49, 0x5c, 0x5f, 0x66, 0x13, 0xdb, 0xbd, 0x15, 0x53, 0x59, 0x3f, 0x15, 0xc3, 0xdd, 0x1a, 0xea, 0xe9}) {
        std::cout << "Хеш посчитан корректно." << std::endl;
        long double time = time_end - time_start;
        long double size = data.size();
        std::cout << "Скорость хеширования: " << size * 7629 / time << " Мб / сек." << std::endl;
    }
    else {
        std::cout << "Хеш посчитан не корректно." << std::endl;
    }
}
int main() {
    Cryptor::init_multithreading(8); //Укажите количество потоков цифрового процессора.


    std::vector<unsigned char> password = {'D', 'o', ' ', 'n', 'o', 't', ' ', 'u', 's', 'e', ' ', 't', 'h', 'i', 's', ' ', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '.', 'I', 't', ' ', 'i', 's', ' ', 'e', 'a', 's', 'y', ' ', 't', 'o', ' ', 'h', 'a', 'c', 'k', '.'}; //Длина пароля должна быть от 8 символов.
    std::vector<unsigned char> key = Cryptor::generate_key_from_password(password, 100000); //В качестве параметра iterations необходимо указать сколько раз будет хешироваться пароль. Принимаются значения от 1 000 до 100 000. Чем больше значение, тем дольше выполняется функция и тем сильнее безопасность. В качестве альтернативы можно использовать функцию AES128::generate_random_key (в этом случае создание пароля не требуется).
    std::vector<std::vector<unsigned char>> key_schedule = AES128::key_expansion(key);


    std::cout << "Тестирование ECB режима." << std::endl;
    ECB_test(key, key_schedule);


    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "Тестирование CTR режима." << std::endl;
    CTR_test(key, key_schedule);


    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "Тестирование хеш функции SHA256." << std::endl;
    SHA256_test();
    return 0;
}