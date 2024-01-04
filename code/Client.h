#ifndef EFFECTIVE_OCTO_SYSTEM_CLIENT_H
#define EFFECTIVE_OCTO_SYSTEM_CLIENT_H

#include "Config.h"
#include "crypto/Edx25519_KeyPair.h"
#include "web/WebClient.h"
#include "crypto/Signator.h"
#include "crypto/Encryptor.h"
#include "crypto/SymKey.h"
#include "Folder.h"
#include "File.h"

#include <string>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>

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

    // User operations
    void listUsers();

    // General operations
    void rename(const std::string& path, const std::string& newName) {
        if (isFolder(path)) {
            renameFolder(path, newName);
        } else {
            renameFile(path, newName);
        }
    }
    void delete_(const std::string& path) {
        if (isFolder(path)) {
            deleteFolder(path);
        } else {
            deleteFile(path);
        }
    }
    void share(const std::string& path, const std::string& username) {
        if (isFolder(path)) {
            shareFolder(path, username);
        } else {
            shareFile(path, username);
        }
    }

    // Folder operations
    void createFolder(const std::string& path);
    void listFolder(const std::string& path);
    void renameFolder(const std::string& path, const std::string& newName);
    void deleteFolder(const std::string& path);

    // File operations
    void uploadFile(const std::string& path, const std::string& localName);
    void downloadFile(const std::string& path);
    void renameFile(const std::string& path, const std::string& newName);
    void deleteFile(const std::string& path);

    // Share operations
    void shareFolder(const std::string& path, const std::string& username);
    void shareFile(const std::string& path, const std::string& username);

private:
    std::string sharedPrefix = "/shared/";
    std::string basePath = "/" + Config::getInstance().getUsername() + "/";

    std::string sanitizePath(const std::string& path, bool addTrailingSlash = false);

    std::string getServerPath(const std::string& path);

    Folder getRootFolder();

    Folder getFolderFromUserPath(const std::string& path);
    File getFileFromUserPath(const std::string& path);

    Folder getSharedFolderFromPath(const std::string& path);
    File getSharedFileFromPath(const std::string& path);

    std::string getFileName(const std::string& path);
    std::string getFolderPath(const std::string& path);
    std::string getSharedPath(const std::string& path);

    bool isFolder(const std::string& path);
    bool isShared(const std::string& path);
};


#endif //EFFECTIVE_OCTO_SYSTEM_CLIENT_H
