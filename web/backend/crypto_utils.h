#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>

std::vector<unsigned char> generate_salt(size_t length = 16);

std::vector<unsigned char> hash_master_password(
    const std::string& password,
    const std::vector<unsigned char>& salt
);

bool verify_master_password(
    const std::string& input_password,
    const std::vector<unsigned char>& stored_salt,
    const std::vector<unsigned char>& stored_hash
);

std::vector<unsigned char> derive_key_from_password(
    const std::string& password,
    const std::vector<unsigned char>& salt
);

std::vector<unsigned char> encrypt_password(
    const std::string& plaintext,
    const std::vector<unsigned char>& key
);

std::string decrypt_password(
    const std::vector<unsigned char>& encrypted_data,
    const std::vector<unsigned char>& key
);


std::vector<unsigned char> from_hex(const std::string& hex);

#endif