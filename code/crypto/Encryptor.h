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
   std::string encrypt(const std::string& content, const SymKey& key)
   {
       unsigned char ciphertext[content.length() + crypto_aead_aes256gcm_ABYTES];
       unsigned long long ciphertext_len;

       if (crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
                                         reinterpret_cast<const unsigned char*>(content.c_str()), content.length(),
                                         NULL, 0,
                                         NULL,
                                         key.getSalt(), key.getKey()) != 0) {
           throw std::runtime_error("Encryption failed");
       }

       return {reinterpret_cast<char*>(ciphertext), ciphertext_len};
   }

   /**
    * Decrypts the content with the given key.
    * @param content Content to decrypt
    * @param key Key to decrypt with
    * @return Decrypted content
    */
   std::string decrypt(const std::string& content, const SymKey& key)
   {
         unsigned char decrypted[content.length() - crypto_aead_aes256gcm_ABYTES];
         unsigned long long decrypted_len;

         if (crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                          NULL,
                                          reinterpret_cast<const unsigned char*>(content.c_str()), content.length(),
                                          NULL, 0,
                                          key.getSalt(), key.getKey()) != 0) {
              throw std::runtime_error("Decryption failed");
         }

         return {reinterpret_cast<char*>(decrypted), decrypted_len};
   }

   /**
    * Encrypts the content with the given key pair.
    * @param content Content to encrypt
    * @param key Key to encrypt with
    * @return Encrypted content
    */
   std::string encrypt(const std::string& content, const Edx25519_KeyPair& key)
   {
       unsigned char ciphertext[crypto_box_SEALBYTES + content.length()];
       if (crypto_box_seal(ciphertext, reinterpret_cast<const unsigned char*>(content.c_str()), content.length(),
                       key.getX25519Pk()) != 0) {
              throw std::runtime_error("Encryption failed");
       }

       return {reinterpret_cast<char*>(ciphertext), crypto_box_SEALBYTES + content.length()};
   }

   /**
    * Decrypts the content with the given key pair.
    * @param content Content to decrypt
    * @param key Key to decrypt with
    * @return Decrypted content
    */
   std::string decrypt(const std::string& content, const Edx25519_KeyPair& key)
   {
       unsigned char decrypted[content.length() - crypto_box_SEALBYTES];
       if (crypto_box_seal_open(decrypted, reinterpret_cast<const unsigned char*>(content.c_str()), content.length(),
                                key.getX25519Pk(), key.getX25519Sk()) != 0) {
                throw std::runtime_error("Decryption failed");
       }

       return {reinterpret_cast<char*>(decrypted), content.length() - crypto_box_SEALBYTES};
   }
};


#endif //EFFECTIVE_OCTO_SYSTEM_ENCRYPTOR_H
