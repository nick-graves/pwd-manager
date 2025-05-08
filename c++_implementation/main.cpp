#include <iostream>
#include <string>
#include <limits>
#include "vault_manager.h"
#include "password_utils.h"
#include <sodium.h>

// function to print main menu
void print_menu() 
{
    std::cout << "\n=== Password Manager ===\n";
    std::cout << "1. Add credential\n";
    std::cout << "2. View credentials\n";
    std::cout << "3. Delete credential\n";
    std::cout << "4. Exit\n";
    std::cout << "Choose an option: ";
}

// entry point for appliaction
int main() 
{
    // initialize libsodium - required for encyrption/decryption/hasing
    if (sodium_init() < 0) 
    {
        std::cerr << "libsodium initialization failed\n";
        return 1;
    }

    // create instance of vault manager for db and keyfile
    VaultManager vault("vault.db", "keyfile.dat");

    // ensure vault is initialized
    if (!vault.initialize()) 
    {
        std::cerr << "Failed to initialize vault.\n";
        return 1;
    }

    std::cout << R"(
__________  __      __________       _____                                             
\______   \/  \    /  \______ \     /     \ _____    ____ _____     ____   ___________ 
 |     ___/\   \/\/   /|    |  \   /  \ /  \\__  \  /    \\__  \   / ___\_/ __ \_  __ \
 |    |     \        / |    `   \ /    Y    \/ __ \|   |  \/ __ \_/ /_/  >  ___/|  | \/
 |____|      \__/\  / /_______  / \____|__  (____  /___|  (____  /\___  / \___  >__|   
                  \/          \/          \/     \/     \/     \//_____/      \/       
    )" << std::endl;
    

    // variable user slection
    int choice;

    // main loop for CLI
    while (true) 
    {
        print_menu();

        // read user input as an int
        if(!(std::cin >> choice)) 
        {
            // clear error flags and ignore invalid input
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid option. Please try again.\n";
            continue;
        }

        // add credential
        if (choice == 1) 
        {
            // clear input buffer
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            // prompt user for name, username, and password
            std::string name, username, password;
            std::cout << "Enter name for this credential: ";
            std::getline(std::cin, name);
            std::cout << "Enter username: ";
            std::getline(std::cin, username);

            // prompt user for randomly generated passowrd
            std::cout << "Use randomly generated password? (y/n): ";
            char use_random;
            std::cin >> use_random;
            std::cin.ignore();

            // call gnerate_random_password() from password_utils
            if (use_random == 'y' || use_random == 'Y') 
            {
                password = generate_random_password();
                std::cout << "Generated password: " << password << "\n";
            } 
            else 
            {
                std::cout << "Enter password: ";
                std::getline(std::cin, password);
            }

            // call addCredential() from vault_manager
            vault.addCredential(name, username, password);

        }
        // view credentials
        else if (choice == 2) 
        {
            // call listCredentials() from vault_manager
            vault.listCredentials();

        }
        // delete credential
        else if (choice == 3) 
        {
            // take credential ID from user
            int id;
            std::cout << "Enter credential ID to delete: ";
            if(!(std::cin >> id)) 
            {
                // clear error flags and ignore invalid input
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cout << "Invalid option. Please try again.\n";
                continue;
            }

            // call deleteCredential() from vault_manager
            vault.deleteCredential(id);

        } 
        // exit application
        else if (choice == 4) 
        {
            std::cout << "Exiting. Goodbye!\n";
            break;

        } 
        else 
        {
            std::cout << "Invalid option. Please try again.\n";
        }
    }

    return 0;
}