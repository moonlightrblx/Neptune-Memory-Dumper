#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <iomanip>

// Substitution table for one encryption layer
const char SUBST_TABLE[26] = {
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P',
    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Z',
    'X', 'C', 'V', 'B', 'N', 'M'
};

// Reverse substitution for decryption
char get_subst_reverse(char c) {
    if (isalpha(c)) {
        for (int i = 0; i < 26; i++) {
            if (SUBST_TABLE[i] == toupper(c)) {
                return static_cast<char>('A' + i);
            }
        }
    }
    return c; // Non-alpha unchanged
}

// Generate rotating XOR key based on seed
std::vector<char> gen_xor_key(size_t len, unsigned int seed) {
    std::vector<char> key(len);
    for (size_t i = 0; i < len; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF; // Simple PRNG
        key[i] = static_cast<char>(seed % 256);
    }
    return key;
}

// Generate shuffle map for character reordering
std::vector<size_t> gen_shuffle_map(size_t len, unsigned int seed) {
    std::vector<size_t> map(len);
    for (size_t i = 0; i < len; i++) map[i] = i;
    std::mt19937 rng(seed);
    std::shuffle(map.begin(), map.end(), rng);
    return map;
}

// Reverse shuffle map for decryption
std::vector<size_t> reverse_shuffle_map(const std::vector<size_t>& map) {
    std::vector<size_t> reverse(map.size());
    for (size_t i = 0; i < map.size(); i++) {
        reverse[map[i]] = i;
    }
    return reverse;
}

// Encrypt function: Apply Substitution -> Shuffle -> XOR
std::vector<unsigned char> encrypt(const std::string& input, unsigned int seed) {
    // Step 1: Substitution
    std::string temp1;
    for (char c : input) {
        if (isalpha(c)) {
            int idx = toupper(c) - 'A';
            temp1 += SUBST_TABLE[idx];
        }
        else {
            temp1 += c;
        }
    }

    // Step 2: Shuffle
    std::vector<size_t> shuffle_map = gen_shuffle_map(input.size(), seed + 1);
    std::string temp2(input.size(), '\0');
    for (size_t i = 0; i < input.size(); i++) {
        temp2[shuffle_map[i]] = temp1[i];
    }

    // Step 3: XOR with rotating key
    std::vector<char> xor_key = gen_xor_key(input.size(), seed);
    std::vector<unsigned char> result;
    for (size_t i = 0; i < input.size(); i++) {
        result.push_back(static_cast<unsigned char>(temp2[i] ^ xor_key[i]));
    }

    return result;
}

// Decrypt function: Reverses XOR -> Unshuffle -> Reverse Substitution
std::string decrypt(const std::vector<unsigned char>& enc_data, size_t len, unsigned int seed) {
    // Step 1: Reverse XOR with rotating key
    std::vector<char> xor_key = gen_xor_key(len, seed);
    std::string temp1;
    for (size_t i = 0; i < len; i++) {
        temp1 += static_cast<char>(enc_data[i] ^ xor_key[i]);
    }

    // Step 2: Reverse shuffle
    std::vector<size_t> shuffle_map = gen_shuffle_map(len, seed + 1);
    std::vector<size_t> unshuffle_map = reverse_shuffle_map(shuffle_map);
    std::string temp2(len, '\0');
    for (size_t i = 0; i < len; i++) {
        temp2[unshuffle_map[i]] = temp1[i];
    }

    // Step 3: Reverse substitution
    std::string result;
    for (char c : temp2) {
        result += get_subst_reverse(c);
    }

    return result;
}

int main() {
    // Fixed seeds for reproducibility
    unsigned int seed1 = 0x1000;
    unsigned int seed2 = 0x2000;
    unsigned int seed3 = 0x3000;

    // Original strings to encrypt
    std::string orig1 = "Test";
    std::string orig2 = "Secret";
    std::string orig3 = "SomeHidden";

    // Encrypt them at runtime
    std::vector<unsigned char> enc1 = encrypt(orig1, seed1);
    std::vector<unsigned char> enc2 = encrypt(orig2, seed2);
    std::vector<unsigned char> enc3 = encrypt(orig3, seed3);

    // Show encrypted bytes for reference
    std::cout << "Encrypted String 1 Bytes: ";
    for (auto b : enc1) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << std::endl;

    std::cout << "Encrypted String 2 Bytes: ";
    for (auto b : enc2) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << std::endl;

    std::cout << "Encrypted String 3 Bytes: ";
    for (auto b : enc3) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << std::endl;

    // Decrypt them
    std::string dec1 = decrypt(enc1, orig1.size(), seed1);
    std::string dec2 = decrypt(enc2, orig2.size(), seed2);
    std::string dec3 = decrypt(enc3, orig3.size(), seed3);

    // Output decrypted strings
    std::cout << "Decrypted String 1: " << dec1 << std::endl;
    std::cout << "Decrypted String 2: " << dec2 << std::endl;
    std::cout << "Decrypted String 3: " << dec3 << std::endl;

    // Keep app running to hold decrypted strings in memory
    std::cout << "App running, strings decrypted in memory. Press Ctrl+C to exit..." << std::endl;
    while (true) {
        Sleep(1000);
        // Reference strings to avoid optimization
        if (GetTickCount() % 5 == 0) {
            std::cout << "Still active: " << dec1[0] << dec2[0] << dec3[0] << std::endl;
        }
    }

    return 0;
}