#include <iostream>
#include <stdexcept>
#include <sstream>
#include <iomanip>

#include "crypto_utils.h"
#include <sodium.h>

// generate salt of the inputed length
std::vector<unsigned char> generate_salt(size_t length) 
{
    // allocate memory for salt
    std::vector<unsigned char> salt(length);

    // fill with random bytes
    randombytes_buf(salt.data(), length);
    return salt;
}

// hashes the master password + salt
std::vector<unsigned char> hash_master_password(const std::string& password, const std::vector<unsigned char>& salt) 
{
    // desiered output hash length
    constexpr size_t HASH_LEN = 32;

    // allocate memory for hash
    std::vector<unsigned char> hash(HASH_LEN);

    // has password using Argon2
    if (crypto_pwhash(
        hash.data(), hash.size(), // output the buffer size (32-bytes for 256-bit hash)
        password.c_str(), password.length(), // input password as raw bytes
        salt.data(), // input salt
        crypto_pwhash_OPSLIMIT_MODERATE, // set moderate limit for CPU usage
        crypto_pwhash_MEMLIMIT_MODERATE, // set moderate limit for RAM usage
        crypto_pwhash_ALG_DEFAULT // algorithm used: Argon2id
    ) != 0) 
    {
        throw std::runtime_error("Master password hashing failed");
    }

    return hash;
}

// verify the inputed password against the stored hash of the master password
bool verify_master_password(const std::string& input_password,const std::vector<unsigned char>& stored_salt,const std::vector<unsigned char>& stored_hash) 
{
    // hash the inputed password with the stored salt
    auto input_hash = hash_master_password(input_password, stored_salt);
    // compare the computed and sotred hash
    return sodium_memcmp(input_hash.data(), stored_hash.data(), stored_hash.size()) == 0;
}

// derive a symmetric key from the master password and salt
std::vector<unsigned char> derive_key_from_password(const std::string& password,const std::vector<unsigned char>& salt) 
{
    // allocate 32-byte (256-bit) key buffer
    std::vector<unsigned char> key(crypto_aead_chacha20poly1305_IETF_KEYBYTES);

    if (crypto_pwhash(
        key.data(), key.size(), // output the buffer size (32-bytes for ChaCha20 key)
        password.c_str(), password.size(), // input password as raw bytes
        salt.data(), // input salt
        crypto_pwhash_OPSLIMIT_MODERATE, // set moderate limit for CPU usage
        crypto_pwhash_MEMLIMIT_MODERATE, // set moderate limit for RAM usage
        crypto_pwhash_ALG_DEFAULT // algorithm used: Argon2id
    ) != 0) 
    {
        throw std::runtime_error("Key derivation failed");
    }

    return key;
}

// encrypt the password using the derived symmetric key
std::vector<unsigned char> encrypt_password(const std::string& plaintext,const std::vector<unsigned char>& key)
{
    // generate a random nonce
    std::vector<unsigned char> nonce(crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // allocate memory for ciphertext
    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_IETF_ABYTES);


    unsigned long long ciphertext_len;

    // encrypt the plaintext using libsodium's AEAD API
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len, // output buffer and actually written length
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(), // input plaintext
        nullptr, 0, nullptr, // no additional data used
        nonce.data(), key.data() // nonce and key
    );

    // prepend nonce to ciphertext for decryption later
    std::vector<unsigned char> combined(nonce);
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    return combined;
}

// decrypt the password using the derived symmetric key
std::string decrypt_password(const std::vector<unsigned char>& encrypted_data,const std::vector<unsigned char>& key)
{
    // check if the encrypted data is long enough to contain nonce
    if (encrypted_data.size() < crypto_aead_chacha20poly1305_IETF_NPUBBYTES) 
    {
        throw std::runtime_error("Encrypted data too short");
    }

    // extract the nonce
    std::vector<unsigned char> nonce(
        encrypted_data.begin(),
        encrypted_data.begin() + crypto_aead_chacha20poly1305_IETF_NPUBBYTES
    );

    // extract the ciphertext
    std::vector<unsigned char> ciphertext(
        encrypted_data.begin() + nonce.size(),
        encrypted_data.end()
    );

    // allocate memory for decrypted plaintext
    std::vector<unsigned char> decrypted(ciphertext.size());
    unsigned long long decrypted_len;

    // decrypt the ciphertext using libsodium's AEAD API
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted.data(), &decrypted_len, // output buffer and actually written length
        nullptr, // no additional data used
        ciphertext.data(), ciphertext.size(), // input ciphertext
        nullptr, 0, // no additional data used
        nonce.data(), key.data() // nonce and key
    ) != 0) 
    {
        throw std::runtime_error("Decryption failed (invalid password or data)");
    }

    return std::string(decrypted.begin(), decrypted.begin() + decrypted_len);
}


// helper converts binary data to a hexadecimal string for easy storage
std::string to_hex(const std::vector<unsigned char>& data) 
{
    std::ostringstream oss;

    // iterate through each byte 
    for (unsigned char byte : data) 
    {
        // convert byte to hex and append to string stream
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}

// helper converts a hexadecimal string back into binary data
std::vector<unsigned char> from_hex(const std::string& hex) 
{
    std::vector<unsigned char> result;

    // iterate over the hex string in pairs
    for (size_t i = 0; i < hex.length(); i += 2) 
    {
        // convert each pair of hex digits to a byte
        unsigned int byte;
        std::istringstream(hex.substr(i, 2)) >> std::hex >> byte;
        result.push_back(static_cast<unsigned char>(byte));
    }
    return result;
}