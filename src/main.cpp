#include <iostream>
#include "Cryptor.hpp"


int main() {
    std::string threads;
    std::string action;
    std::string path;
    std::string string_password;

    std::cout << "Укажите число потоков ЦП: ";
    std::getline(std::cin, threads);

    std::cout << "Выберите действие (1 - шифрование, 2 - дешифрование): ";
    std::getline(std::cin, action);

    std::cout << "Укажите путь к файлу: ";
    std::getline(std::cin, path);

    std::cout << "Введите пароль: ";
    std::getline(std::cin, string_password);

    Cryptor::init_multithreading(std::stoi(threads));
    std::vector<unsigned char> password(string_password.begin(), string_password.end());
    try {
        std::vector<unsigned char> key = Cryptor::generate_key_from_password(password, 100000);
        std::vector<std::vector<unsigned char>> key_schedule = AES128::key_expansion(key);

        if (action == "1") {
            try {
                Cryptor::encrypt_file(path, path, "CTR_mode", key, key_schedule);
                std::cout << "\e[1;32m" << "Шифрование успешно завершено." << "\e[0m" << std::endl;
            }
            catch (const char* message) {
                std::cout << "\e[1;31m" << "Во время шифрования было выброшено исключение. Вот его текст: " << message << "\e[0m" << std::endl;
            }
        }
        else if (action == "2") {
            try {
                Cryptor::decrypt_file(path, path, key, key_schedule);
                std::cout << "\e[1;32m" << "Дешифрование успешно завершено." << "\e[0m" << std::endl;
            }
            catch (const char* message) {
                std::cout << "\e[1;31m" << "Во время дешифрования было выброшено исключение. Вот его текст: " << message << "\e[0m" << std::endl;
            }
        }
        else std::cout << "\e[1;31m" << "Неизвестное действие." << "\e[0m" << std::endl;
    }
    catch (const char* message) {
        std::cout << "\e[1;31m" << "Во время создания ключа было выброшено исключение. Вот его текст: " << message << "\e[0m" << std::endl;
    }

    return 0;
}