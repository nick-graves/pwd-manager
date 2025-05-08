#include <iostream>
#include <string>

#include "password_utils.h"
#include <sodium.h>


// function to generate a random string of a given length
std::string generate_random_password(size_t length) 
{
    // list of chracters
    const std::string charset =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}<>?";

    // initalize string and pre-alloacte memory
    std::string password;
    password.reserve(length);

    // loop through the inputed length
    for (size_t i = 0; i < length; ++i) 
    {
        // use libsodium randombytes_uniform to get a random index
        size_t index = randombytes_uniform(charset.size());
        // append chracter to random password
        password += charset[index];
    }

    return password;
}