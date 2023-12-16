#ifndef EFFECTIVE_OCTO_SYSTEM_CLIENT_H
#define EFFECTIVE_OCTO_SYSTEM_CLIENT_H

#include "ConnectionStatus.h"
#include "File.h"
#include "Folder.h"
#include "Config.h"

#include <string>

#define PASSWORD_HASH_LENGTH 64

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
