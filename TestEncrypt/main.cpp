#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <iomanip>

const char subst_table[26] = {
    'Q','W','E','R','T','Y','U','I','O','P',
    'A','S','D','F','G','H','J','K','L','Z',
    'X','C','V','B','N','M'
};

char get_subst_reverse(char c) {
    if (isalpha(c)) {
        for (int i = 0; i < 26; i++) {
            if (subst_table[i] == toupper(c))
                return static_cast<char>('A' + i);
        }
    }
    return c;
}

std::vector<char> gen_xor_key(size_t len, unsigned int seed) {
    std::vector<char> key(len);
    for (size_t i = 0; i < len; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        key[i] = static_cast<char>(seed % 256);
    }
    return key;
}

std::vector<size_t> gen_shuffle_map(size_t len, unsigned int seed) {
    std::vector<size_t> map(len);
    for (size_t i = 0; i < len; i++)
        map[i] = i;

    std::mt19937 rng(seed);
    std::shuffle(map.begin(), map.end(), rng);
    return map;
}

/* required to invert the permutation during decryption */
std::vector<size_t> reverse_shuffle_map(const std::vector<size_t>& map) {
    std::vector<size_t> reverse(map.size());
    for (size_t i = 0; i < map.size(); i++)
        reverse[map[i]] = i;
    return reverse;
}

std::vector<unsigned char> encrypt(const std::string& input, unsigned int seed) {
    std::string sub;
    for (char c : input) {
        if (isalpha(c))
            sub += subst_table[toupper(c) - 'A'];
        else
            sub += c;
    }

    std::vector<size_t> shuffle_map = gen_shuffle_map(input.size(), seed + 1);
    std::string shuffled(input.size(), '\0');
    for (size_t i = 0; i < input.size(); i++)
        shuffled[shuffle_map[i]] = sub[i];

    std::vector<char> xor_key = gen_xor_key(input.size(), seed);
    std::vector<unsigned char> out(input.size());
    for (size_t i = 0; i < input.size(); i++)
        out[i] = static_cast<unsigned char>(shuffled[i] ^ xor_key[i]);

    return out;
}

std::string decrypt(const std::vector<unsigned char>& enc, size_t len, unsigned int seed) {
    std::vector<char> xor_key = gen_xor_key(len, seed);
    std::string unxor;
    for (size_t i = 0; i < len; i++)
        unxor += static_cast<char>(enc[i] ^ xor_key[i]);

    std::vector<size_t> shuffle_map = gen_shuffle_map(len, seed + 1);
    std::vector<size_t> unshuffle = reverse_shuffle_map(shuffle_map);

    std::string unshuffled(len, '\0');
    for (size_t i = 0; i < len; i++)
        unshuffled[unshuffle[i]] = unxor[i];

    std::string out;
    for (char c : unshuffled)
        out += get_subst_reverse(c);

    return out;
}

int main() {
    unsigned int seed1 = 0x1000;
    unsigned int seed2 = 0x2000;
    unsigned int seed3 = 0x3000;

    std::string orig1 = "Test";
    std::string orig2 = "Secret";
    std::string orig3 = "SomeHidden";

    auto enc1 = encrypt(orig1, seed1);
    auto enc2 = encrypt(orig2, seed2);
    auto enc3 = encrypt(orig3, seed3);

    auto print_hex = [](const std::vector<unsigned char>& v) {
        for (auto b : v)
            std::cout << "0x" << std::hex << std::setw(2)
            << std::setfill('0') << (int)b << " ";
        std::cout << std::dec << std::endl;
        };

    std::cout << "Encrypted String 1 Bytes: ";
    print_hex(enc1);
    std::cout << "Encrypted String 2 Bytes: ";
    print_hex(enc2);
    std::cout << "Encrypted String 3 Bytes: ";
    print_hex(enc3);

    std::string dec1 = decrypt(enc1, orig1.size(), seed1);
    std::string dec2 = decrypt(enc2, orig2.size(), seed2);
    std::string dec3 = decrypt(enc3, orig3.size(), seed3);

    std::cout << "Decrypted String 1: " << dec1 << std::endl;
    std::cout << "Decrypted String 2: " << dec2 << std::endl;
    std::cout << "Decrypted String 3: " << dec3 << std::endl;

    std::cout << "App running, strings decrypted in memory. Press Ctrl+C to exit..." << std::endl;
    while (true) {
        Sleep(1000);
        if (GetTickCount() % 5 == 0)
            std::cout << dec1[0] << dec2[0] << dec3[0] << std::endl;
    }

    return 0;
}
