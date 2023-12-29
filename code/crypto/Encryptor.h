#ifndef EFFECTIVE_OCTO_SYSTEM_ENCRYPTOR_H
#define EFFECTIVE_OCTO_SYSTEM_ENCRYPTOR_H

#include <string>
#include "SymKey.h"
#include "Edx25519_KeyPair.h"

namespace Encryptor
{
   /**
    * Encrypts the content with the given key.
    * @param content Content to encrypt
    * @param key Key to encrypt with
    * @return Encrypted content
    */
   std::string encrypt(const std::string& content, const SymKey& key);

   /**
    * Decrypts the content with the given key.
    * @param content Content to decrypt
    * @param key Key to decrypt with
    * @return Decrypted content
    */
   std::string decrypt(const std::string& content, const SymKey& key);

   /**
    * Encrypts the content with the given key pair.
    * @param content Content to encrypt
    * @param key Key to encrypt with
    * @return Encrypted content
    */
   std::string encrypt(const std::string& content, const Edx25519_KeyPair& key);

   /**
    * Decrypts the content with the given key pair.
    * @param content Content to decrypt
    * @param key Key to decrypt with
    * @return Decrypted content
    */
   std::string decrypt(const std::string& content, const Edx25519_KeyPair& key);
}


#endif //EFFECTIVE_OCTO_SYSTEM_ENCRYPTOR_H
