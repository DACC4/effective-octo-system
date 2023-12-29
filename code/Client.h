#ifndef EFFECTIVE_OCTO_SYSTEM_CLIENT_H
#define EFFECTIVE_OCTO_SYSTEM_CLIENT_H

#include "File.h"
#include "Folder.h"
#include "Config.h"
#include "crypto/Edx25519_KeyPair.h"
#include "web/WebClient.h"
#include "crypto/Signator.h"
#include "crypto/Encryptor.h"
#include "crypto/SymKey.h"

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
    void logoutUser(const std::string& username);
};


#endif //EFFECTIVE_OCTO_SYSTEM_CLIENT_H
