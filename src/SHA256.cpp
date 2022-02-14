#include "SHA256.hpp"


static const std::array<unsigned int, 64> K = {0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
                                               0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
                                               0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                                               0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
                                               0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
                                               0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                                               0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
                                               0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};
std::vector<unsigned char> SHA256::get_hash(std::vector<unsigned char> message) {
    unsigned long long message_original_size_in_bits = message.size() * 8;
    message.push_back(0x80);
    while ((message.size() + 8) % 64 != 0) {
        message.push_back(0x00);
    }
    unsigned char buffer_8_bytes[sizeof(message_original_size_in_bits)];
    memcpy(buffer_8_bytes, &message_original_size_in_bits, sizeof(message_original_size_in_bits));
    for (int i = sizeof(buffer_8_bytes) - 1; i >= 0; i = i - 1) {
        message.push_back(buffer_8_bytes[i]);
    }
    std::vector<std::vector<unsigned char>> words(64);
    for (int i = 0; i < 64; i = i + 1) {
        words[i].resize(4);
    }
    unsigned int word_j_minus_16, word_j_minus_15, word_j_minus_7, word_j_minus_2, word_j;
    unsigned char buffer_4_bytes[sizeof(word_j)];
    unsigned int s0, s1;
    unsigned int h0 = 0x6A09E667;
    unsigned int h1 = 0xBB67AE85;
    unsigned int h2 = 0x3C6EF372;
    unsigned int h3 = 0xA54FF53A;
    unsigned int h4 = 0x510E527F;
    unsigned int h5 = 0x9B05688C;
    unsigned int h6 = 0x1F83D9AB;
    unsigned int h7 = 0x5BE0CD19;
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int ch;
    unsigned int ma;
    unsigned int temp1, temp2;
    for (unsigned long long i = 0; i < message.size(); i = i + 64) {
        for (int j = 0; j < 16; j = j + 1) {
            for (int k = 0; k < 4; k = k + 1) {
                words[j][k] = message[i + j * 4 + k];
            }
        }
        for (int j = 16; j < 64; j = j + 1) {
            word_j_minus_16 = SHA256::_convert_word_to_unsigned_int(words[j - 16]);
            word_j_minus_15 = SHA256::_convert_word_to_unsigned_int(words[j - 15]);
            word_j_minus_7 = SHA256::_convert_word_to_unsigned_int(words[j - 7]);
            word_j_minus_2 = SHA256::_convert_word_to_unsigned_int(words[j - 2]);
            s0 = SHA256::_rotr(word_j_minus_15, 7) ^ SHA256::_rotr(word_j_minus_15, 18) ^ (word_j_minus_15 >> 3);
            s1 = SHA256::_rotr(word_j_minus_2, 17) ^ SHA256::_rotr(word_j_minus_2, 19) ^ (word_j_minus_2 >> 10);
            word_j = word_j_minus_16 + s0 + word_j_minus_7 + s1;
            memcpy(buffer_4_bytes, &word_j, sizeof(word_j));
            for (int k = sizeof(buffer_4_bytes) - 1; k >= 0; k = k - 1) {
                words[j][sizeof(buffer_4_bytes) - k - 1] = buffer_4_bytes[k];
            }
        }
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;
        for (int j = 0; j < 64; j = j + 1) {
            s0 = SHA256::_rotr(a, 2) ^ SHA256::_rotr(a, 13) ^ SHA256::_rotr(a, 22);
            s1 = SHA256::_rotr(e, 6) ^ SHA256::_rotr(e, 11) ^ SHA256::_rotr(e, 25);
            ch = (e & f) ^ ((~e) & g);
            ma = (a & b) ^ (a & c) ^ (b & c);
            temp1 = (unsigned long long)(h + s1 + ch + K[j] + SHA256::_convert_word_to_unsigned_int(words[j])) % 4294967296;
            temp2 = s0 + ma;
            h = g;
            g = f;
            f = e;
            e = (unsigned long long)(d + temp1) % 4294967296;
            d = c;
            c = b;
            b = a;
            a = (unsigned long long)(temp1 + temp2) % 4294967296;
        }
        h0 = (unsigned long long)(h0 + a) % 4294967296;
        h1 = (unsigned long long)(h1 + b) % 4294967296;
        h2 = (unsigned long long)(h2 + c) % 4294967296;
        h3 = (unsigned long long)(h3 + d) % 4294967296;
        h4 = (unsigned long long)(h4 + e) % 4294967296;
        h5 = (unsigned long long)(h5 + f) % 4294967296;
        h6 = (unsigned long long)(h6 + g) % 4294967296;
        h7 = (unsigned long long)(h7 + h) % 4294967296;
    }
    std::vector<unsigned char> hash;
    hash.reserve(32);
    memcpy(buffer_4_bytes, &h0, sizeof(h0));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    memcpy(buffer_4_bytes, &h1, sizeof(h1));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    memcpy(buffer_4_bytes, &h2, sizeof(h2));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    memcpy(buffer_4_bytes, &h3, sizeof(h3));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    memcpy(buffer_4_bytes, &h4, sizeof(h4));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    memcpy(buffer_4_bytes, &h5, sizeof(h5));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    memcpy(buffer_4_bytes, &h6, sizeof(h6));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    memcpy(buffer_4_bytes, &h7, sizeof(h7));
    for (int i = sizeof(buffer_4_bytes) - 1; i >= 0; i = i - 1) {
        hash.push_back(buffer_4_bytes[i]);
    }
    return hash;
}
unsigned int SHA256::_rotr(unsigned int number_first, unsigned int number_second) {
    return (number_first >> number_second) | (number_first << (sizeof(number_first) * 8 - number_second));
}
unsigned int SHA256::_convert_word_to_unsigned_int(std::vector<unsigned char> word) {
    return (unsigned int)word[0] * 16777216 + (unsigned int)word[1] * 65536 + (unsigned int)word[2] * 256 + word[3];
}