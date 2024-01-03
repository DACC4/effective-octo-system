#include "SymKey.h"

SymKey SymKey::random()
{
    SymKey key = SymKey();
    randombytes_buf(key.salt, sizeof key.salt);
    randombytes_buf(key.key, sizeof key.key);
    return key;
}

SymKey SymKey::deriveFromPassword(const std::string& password)
{
    SymKey key = SymKey();

    // Generate random salt
    randombytes_buf(key.salt, sizeof key.salt);

    // Generate key from password using salt
    if (crypto_pwhash(key.key, sizeof key.key, password.c_str(), password.size(), key.salt, SYMKEY_PASSWORD_OPSLIMIT, SYMKEY_PASSWORD_MEMLIMIT, SYMKEY_ALG) != 0)
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
    SymKey key = SymKey();

    // Copy salt
    std::copy(salt, salt + sizeof key.salt, key.salt);

    // Generate key from password using salt
    if (crypto_pwhash(key.key, sizeof key.key, password.c_str(), password.size(), key.salt, SYMKEY_PASSWORD_OPSLIMIT, SYMKEY_PASSWORD_MEMLIMIT, SYMKEY_ALG) != 0)
    {
        throw std::runtime_error("Failed to generate key from password");
    }

    return key;
}

SymKey SymKey::deriveFromKey(SymKey key)
{
    SymKey newKey = SymKey();

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

SymKey SymKey::deriveFromKey(SymKey key, const std::string& salt)
{
    SymKey newKey = SymKey();

    // Copy salt
    std::string tmp = base64_decode(salt);
    std::copy(tmp.begin(), tmp.end(), newKey.salt);

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
    SymKey newKey = SymKey();

    // Generate random salt
    randombytes_buf(newKey.salt, sizeof newKey.salt);

    // Copy key
    std::copy(key.key, key.key + sizeof newKey.key, newKey.key);

    return newKey;
}

SymKey SymKey::fromKey(SymKey key, const std::string& salt)
{
    SymKey newKey = SymKey();

    // Copy salt
    std::string tmp = base64_decode(salt);
    std::copy(tmp.begin(), tmp.end(), newKey.salt);

    // Copy key
    std::copy(key.key, key.key + sizeof newKey.key, newKey.key);

    return newKey;
}

SymKey SymKey::fromBase64(const std::string& keyBase64, const std::string& saltBase64) {
    SymKey key = SymKey();

    // Decode key
    std::string tmp = base64_decode(keyBase64);
    std::copy(tmp.begin(), tmp.end(), key.key);

    // Decode salt
    tmp = base64_decode(saltBase64);
    std::copy(tmp.begin(), tmp.end(), key.salt);

    return key;
}
