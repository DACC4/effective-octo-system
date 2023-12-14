#ifndef EFFECTIVE_OCTO_SYSTEM_CLIENT_H
#define EFFECTIVE_OCTO_SYSTEM_CLIENT_H

#include "ConnectionStatus.h"
#include "File.h"
#include "Folder.h"
#include "Config.h"

#include <string>

class Client
{
   ConnectionStatus status;
   std::string session_token;

public:
    Client() {
        if(Config::getInstance().getSessionToken().empty()) {
            status = ConnectionStatus::UNAUTHENTICATED;
        } else {
            status = ConnectionStatus::AUTHENTICATED;
            session_token = Config::getInstance().getSessionToken();
        }
    }

    ~Client() = default;

    // Authentication
    void registerUser(const std::string& username, const std::string& password);
};


#endif //EFFECTIVE_OCTO_SYSTEM_CLIENT_H
