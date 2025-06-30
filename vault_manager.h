#ifndef VAULT_MANAGER_H
#define VAULT_MANAGER_H

#include <string>
#include <vector>
#include <sqlite3.h>
#include "crypto_utils.h"

class VaultManager 
{
public:
    VaultManager(const std::string& db_path, const std::string& keyfile_path);

    bool initialize(); 
    void addCredential(const std::string& name, const std::string& username, const std::string& password);
    void deleteCredential(int id);
    void listCredentials();
    std::vector<std::tuple<int, std::string, std::string, std::string>> exportCredentials();

private:
    std::string db_path_;
    std::string keyfile_path_;
    sqlite3* db_;
    std::vector<unsigned char> symmetric_key_;

    bool setupDatabase();
    bool setupMasterPassword();
    bool checkPassword();
    bool loadKeyfile(std::vector<unsigned char>& salt, std::vector<unsigned char>& hash);
    bool writeKeyfile(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& hash);
    bool checkCredential(int id);
};

#endif