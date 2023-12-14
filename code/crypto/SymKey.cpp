#include "SymKey.h"

SymKey SymKey::random()
{
    SymKey key;
    randombytes_buf(key.salt, sizeof key.salt);
    randombytes_buf(key.key, sizeof key.key);
    return key;
}

SymKey SymKey::deriveFromPassword(const std::string& password)
{
    SymKey key;

    // Generate random salt
    randombytes_buf(key.salt, sizeof key.salt);

    // Generate key from password using salt
    if (crypto_pwhash(key.key, sizeof key.key, password.c_str(), password.size(), key.salt, SYMKEY_OPSLIMIT, SYMKEY_MEMLIMIT, SYMKEY_ALG) != 0)
    {
        throw std::runtime_error("Failed to generate key from password");
    }

    return key;
}

SymKey SymKey::deriveFromPassword(const std::string& password, const std::string& username)
{
    // Hash username to get salt
    unsigned char hash[SYMKEY_SALT_SIZE];
    crypto_generichash(hash, sizeof hash,
                       (const unsigned char*)username.c_str(), username.size(),
                       nullptr, 0);

    // Generate key from password using salt
    return deriveFromPassword(password, hash);
}

SymKey SymKey::deriveFromPassword(const std::string& password, unsigned char salt[SYMKEY_SALT_SIZE])
{
    SymKey key;

    // Copy salt
    std::copy(salt, salt + sizeof key.salt, key.salt);

    // Generate key from password using salt
    if (crypto_pwhash(key.key, sizeof key.key, password.c_str(), password.size(), key.salt, SYMKEY_OPSLIMIT, SYMKEY_MEMLIMIT, SYMKEY_ALG) != 0)
    {
        throw std::runtime_error("Failed to generate key from password");
    }

    return key;
}

SymKey SymKey::deriveFromKey(SymKey key)
{
    SymKey newKey;

    // Generate random salt
    randombytes_buf(newKey.salt, sizeof newKey.salt);

    // Derive new key from key using salt
    if (crypto_pwhash(newKey.key, sizeof newKey.key, reinterpret_cast<const char* const>(key.key), sizeof key.key, newKey.salt, SYMKEY_OPSLIMIT,
                      SYMKEY_MEMLIMIT, SYMKEY_ALG) != 0)
    {
        throw std::runtime_error("Failed to generate key from key");
    }

    return key;
}

SymKey SymKey::deriveFromKey(SymKey key, unsigned char salt[SYMKEY_SALT_SIZE])
{
    SymKey newKey;

    // Copy salt
    std::copy(salt, salt + sizeof newKey.salt, newKey.salt);

    // Derive new key from key using salt
    if (crypto_pwhash(newKey.key, sizeof newKey.key, reinterpret_cast<const char* const>(key.key), sizeof key.key, newKey.salt, SYMKEY_OPSLIMIT,
                      SYMKEY_MEMLIMIT, SYMKEY_ALG) != 0)
    {
        throw std::runtime_error("Failed to generate key from key");
    }

    return key;
}

SymKey SymKey::fromKey(SymKey key)
{
    SymKey newKey;

    // Generate random salt
    randombytes_buf(newKey.salt, sizeof newKey.salt);

    // Copy key
    std::copy(key.key, key.key + sizeof newKey.key, newKey.key);

    return newKey;
}

SymKey SymKey::fromKey(SymKey key, unsigned char salt[SYMKEY_SALT_SIZE])
{
    SymKey newKey;

    // Copy salt
    std::copy(salt, salt + sizeof newKey.salt, newKey.salt);

    // Copy key
    std::copy(key.key, key.key + sizeof newKey.key, newKey.key);

    return newKey;
}
