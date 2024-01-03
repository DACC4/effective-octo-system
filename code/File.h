#ifndef EFFECTIVE_OCTO_SYSTEM_FILE_H
#define EFFECTIVE_OCTO_SYSTEM_FILE_H

#include <string>
#include <nlohmann/json.hpp>
#include "crypto/SymKey.h"

class File
{
   std::string name;
   std::string path;
   SymKey key;
   SymKey dataKey;

public:
    File(const std::string& name, const std::string& path, const SymKey& key, const SymKey& dataKey);
    ~File() = default;

    std::string getName() const { return name;}
    std::string getPath() const { return path;}
    SymKey getKey() const { return key;}
    SymKey getDataKey() const { return dataKey;}
};


#endif //EFFECTIVE_OCTO_SYSTEM_FILE_H
