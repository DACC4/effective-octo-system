#ifndef EFFECTIVE_OCTO_SYSTEM_SYMKEY_H
#define EFFECTIVE_OCTO_SYSTEM_SYMKEY_H

#include <sodium.h>
#include <string>

#define SYMKEY_SALT_SIZE crypto_aead_aes256gcm_KEYBYTES
#define SYMKEY_KEY_SIZE crypto_aead_aes256gcm_KEYBYTES
#define SYMKEY_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define SYMKEY_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE
#define SYMKEY_ALG crypto_pwhash_ALG_ARGON2ID13

class SymKey
{
   unsigned char salt[SYMKEY_SALT_SIZE];
   unsigned char key[SYMKEY_KEY_SIZE];

   SymKey() = default;

public:
   unsigned char const* getSalt() const
   {
       return const_cast<unsigned char*>(salt);
   }

   unsigned char const* getKey() const
   {
       return const_cast<unsigned char*>(key);
   }

   /**
    * Generates a SymKey from random key and random nonce.
    * @return SymKey
    */
   static SymKey random();

   /**
    * Derives a SymKey from a password with a random salt.
    * @param password Password
    * @return SymKey generated from password
    */
   static SymKey deriveFromPassword(const std::string& password);

   /**
    * Derives a SymKey from a password with a username as salt.
    * @param password Password
    * @param username Username to use as salt
    * @return SymKey generated from password and salt
    */
    static SymKey deriveFromPassword(const std::string& password, const std::string& username);

   /**
    * Derives a SymKey from a password with a given salt.
    * @param password Password
    * @param salt Salt
    * @return SymKey generated from password and salt
    */
   static SymKey deriveFromPassword(const std::string& password, unsigned char salt[SYMKEY_SALT_SIZE]);

   /**
    * Derives a SymKey from a SymKey with a random salt.
    * @param key SymKey to derive from
    * @return SymKey generated from key
    */
   static SymKey deriveFromKey(SymKey key);

   /**
    * Derives a SymKey from a SymKey with a given salt.
    * @param key SymKey to derive from
    * @param salt Salt
    * @return SymKey generated from key and salt
    */
   static SymKey deriveFromKey(SymKey key, unsigned char salt[SYMKEY_SALT_SIZE]);

   /**
    * Generates a SymKey from a given key. Will use the same key but a random salt.
    * @param key Key to generate SymKey from
    * @return SymKey generated from key with a new random salt
    */
   static SymKey fromKey(SymKey key);

   /**
    * Generates a SymKey from a given key and salt.
    * @param key Key to generate SymKey from
    * @param salt Salt to use
    * @return SymKey generated from key and salt
    */
   static SymKey fromKey(SymKey key, unsigned char salt[SYMKEY_SALT_SIZE]);
};

#endif //EFFECTIVE_OCTO_SYSTEM_SYMKEY_H
