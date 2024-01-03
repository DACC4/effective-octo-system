#ifndef EFFECTIVE_OCTO_SYSTEM_CLIENT_H
#define EFFECTIVE_OCTO_SYSTEM_CLIENT_H

#include "Config.h"
#include "crypto/Edx25519_KeyPair.h"
#include "web/WebClient.h"
#include "crypto/Signator.h"
#include "crypto/Encryptor.h"
#include "crypto/SymKey.h"
#include "Folder.h"

#include <string>
#include <nlohmann/json.hpp>
#include <iostream>

class Client
{

public:
    Client() = default;
    ~Client() = default;

    // Authentication
    void registerUser(const std::string& username, const std::string& password);
    void loginUser(const std::string& username, const std::string& password);
    void changePassword(const std::string& newPassword);
    void logoutUser();

    // Folder operations
    void createFolder(const std::string& path, const std::string& name);
    Folder getFolder(const std::string& path);
    void listFolder(const std::string& path);

private:
    Folder getRootFolder();
    Folder getFolderFromUserPath(const std::string& path);
};


#endif //EFFECTIVE_OCTO_SYSTEM_CLIENT_H
