#ifndef EFFECTIVE_OCTO_SYSTEM_FOLDER_H
#define EFFECTIVE_OCTO_SYSTEM_FOLDER_H

#include <string>
#include <nlohmann/json.hpp>
#include "crypto/SymKey.h"

class Folder
{
    std::string name;
    std::string path;
    SymKey key;

public:
    Folder(const std::string& name, const std::string& path, const SymKey& key);
    ~Folder() = default;

    std::string getName() const { return name;}
    std::string getPath() const { return path;}
    SymKey getKey() const { return key;}
};


#endif //EFFECTIVE_OCTO_SYSTEM_FOLDER_H
