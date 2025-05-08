#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

#include "vault_manager.h"
#include "crypto_utils.h"

// valut manager constructor for database and keyfile
VaultManager::VaultManager(const std::string& db_path, const std::string& keyfile_path)
    : db_path_(db_path), keyfile_path_(keyfile_path), db_(nullptr) {}


// master password and database initialization
bool VaultManager::initialize() 
{
    // check if keyfile exists, if not create one
    if (!std::filesystem::exists(keyfile_path_)) 
    {
        return setupMasterPassword() && setupDatabase();
    } 
    // if keyfile exists load and verify the master password
    else 
    {
        return checkPassword() && setupDatabase();
    }
}

// setup the master password and write to keyfile
bool VaultManager::setupMasterPassword() 
{
    // prompt user for master password and confirm
    std::string password, confirm;
    std::cout << "Create a master password: ";
    std::getline(std::cin, password);
    std::cout << "Confirm master password: ";
    std::getline(std::cin, confirm);

    // check if passwords match
    if (password != confirm) 
    {
        std::cerr << "Passwords do not match.\n";
        return false;
    }

    // generate salt and hash the master password
    auto salt = generate_salt();
    auto hash = hash_master_password(password, salt);

    // derive symmetric key from password and salt
    symmetric_key_ = derive_key_from_password(password, salt);

    return writeKeyfile(salt, hash);
}


// verify the master password by hashing and comparing with stored hash
bool VaultManager::checkPassword() 
{
    // read hash and salt from keyfile
    std::vector<unsigned char> salt, hash;
    if (!loadKeyfile(salt, hash)) return false;

    // prompt user for master password
    std::string password;
    std::cout << "Enter master password: ";
    std::getline(std::cin, password);

    // call verify_master_password() from crypto_utils to compute hash of inputed password
    if (!verify_master_password(password, salt, hash)) {
        std::cerr << "Incorrect master password.\n";
        return false;
    }

    // call derive_key_from_password() from crypto_utils to derive symmetric key
    symmetric_key_ = derive_key_from_password(password, salt);
    return true;
}

// load the keyfile and extract the salt and hash
bool VaultManager::loadKeyfile(std::vector<unsigned char>& salt, std::vector<unsigned char>& hash) 
{
    std::ifstream file(keyfile_path_);
    if (!file) return false;

    std::string line;
    std::getline(file, line);

    // expect format in hex: <salt>||<hash>
    size_t delim = line.find("||");
    if (delim == std::string::npos) return false;

    // convert hex strings to byte vectors
    salt = from_hex(line.substr(0, delim));
    hash = from_hex(line.substr(delim + 2));
    return true;
}

// write the salt and hash to the keyfile
bool VaultManager::writeKeyfile(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& hash) 
{
    // open file for writing
    std::ofstream file(keyfile_path_);
    if (!file) return false;

    // write salt and hash in hex format with "||" delimiter
    file << to_hex(salt) << "||" << to_hex(hash);
    return true;
}

// setup the database and create the credentials table if it does not exist
bool VaultManager::setupDatabase() 
{
    // open the SQLite database
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc) 
    {
        std::cerr << "Cannot open DB: " << sqlite3_errmsg(db_) << "\n";
        return false;
    }

    // SQL schema to hold credentials
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        );
    )";

    // execute the SQL statement
    char* errmsg;
    rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) 
    {
        std::cerr << "SQL error: " << errmsg << "\n";
        sqlite3_free(errmsg);
        return false;
    }

    return true;
}


// check if the credential with the given ID exists in the database
bool VaultManager::checkCredential(int id)
{
    // prepare SQL statment
    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM credentials WHERE id = ? LIMIT 1";

    // compile the SQL statement
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) 
    {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << "\n";
        return false;
    }

    // bind the provided ID to the SQL query parameter (1-based index)
    sqlite3_bind_int(stmt, 1, id);

    // step the statement: if it returns a row, the ID exists
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);

    // finalize to clean up memory
    sqlite3_finalize(stmt);
    return found;
}

// add a new credential to the database
void VaultManager::addCredential(const std::string& name, const std::string& username, const std::string& password) 
{
    // encrypt the password with the symmetric key
    auto encrypted = encrypt_password(password, symmetric_key_);

    // prepare the SQL statement to insert the credential
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO credentials (name, username, password) VALUES (?, ?, ?)";

    // bind data to the SQL statement
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, encrypted.data(), encrypted.size(), SQLITE_TRANSIENT);

    // execute statment and free memory
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    std::cout << "Credential added.\n";
}

// delete a credential from the database
void VaultManager::deleteCredential(int id) 
{
    // check to see if id exists
    if (!checkCredential(id)) 
    {
        std::cerr << "Credential with ID " << id << " does not exist.\n";
        return;
    }

    // prepare the SQL statement to delete the credential
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM credentials WHERE id = ?";

    // bind data to the SQL statement
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, id);

    // execute statement and free memory
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    std::cout << "Credential deleted.\n";
}

// list all credentials in the database
void VaultManager::listCredentials() 
{
    // prepare the SQL statement to select all credentials
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, name, username, password FROM credentials";
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    // iterate through all rows
    while (sqlite3_step(stmt) == SQLITE_ROW) 
    {
        // extract data from current row
        int id = sqlite3_column_int(stmt, 0);
        std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

        // copy encryped password to blob
        const unsigned char* blob = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 3));
        int blob_len = sqlite3_column_bytes(stmt, 3);
        std::vector<unsigned char> encrypted(blob, blob + blob_len);

        std::string decrypted;

        // decrypt the password using the symmetric key
        try 
        {
            decrypted = decrypt_password(encrypted, symmetric_key_);
        } 
        catch (...) 
        {
            decrypted = "<decryption failed>";
        }

        // print the credential details
        std::cout << "ID: " << id << " | Name: " << name << " | Username: " << username << " | Password: " << decrypted << "\n";
    }

    // free memory
    sqlite3_finalize(stmt);
}
