#include "File.h"

File::File(const std::string& name, const std::string& path, const SymKey& key, const SymKey& dataKey) : name(name), path(path), key(key),
dataKey(dataKey)
{
}