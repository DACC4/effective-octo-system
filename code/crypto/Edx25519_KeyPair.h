#ifndef EFFECTIVE_OCTO_SYSTEM_EDX25519_KEYPAIR_H
#define EFFECTIVE_OCTO_SYSTEM_EDX25519_KEYPAIR_H

#include <sodium.h>
#include "../lib/base64.h"
#include "SymKey.h"

class Edx25519_KeyPair
{
   /**
    * ed25519 public key
    */
   unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];

   /**
    * ed25519 secret key
    */
   unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];

   /**
    * x25519 public key
    */
   unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES];

   /**
    * x25519 secret key
    */
   unsigned char x25519_sk[crypto_scalarmult_curve25519_BYTES];

public:
   /**
    * Generates a random ed25519 keypair.
    */
   Edx25519_KeyPair();

   /**
    * Create a keypair from a base64 encoded secret key and a base64 encoded public key.
    * @param base64_sk Base64 encoded secret key
    * @param base64_pk Base64 encoded public key
    */
   Edx25519_KeyPair(const std::string& base64_sk, const std::string& base64_pk);

   /**
    * Create a keypair from an encrypted base64 encoded secret key and a base64 encoded public key.
    * @param encrypted_base64_sk Encrypted base64 encoded secret key
    * @param base64_pk Base64 encoded public key
    * @param key SymKey to decrypt with
    */
   Edx25519_KeyPair(const std::string& encrypted_base64_sk, const std::string& base64_pk, const SymKey& key);

   /**
    * Create a keypair from a known public key
    * @param base64_pk Base64 encoded public key
    */
    Edx25519_KeyPair(const std::string& base64_pk);

   /**
    * Default destructor.
    */
   ~Edx25519_KeyPair() = default;

   /**
    * Get ed25519 public key as base64 string.
    * @return Base64 string
    */
   std::string pk_to_base64();

   /**
    * Get ed25519 secret key as base64 string. NOT ENCRYPTED!
    * @return Base64 string
    */
   std::string sk_to_base64();

   /**
    * Get ed25519 public key (to be used for signing)
    * @return Public key
    */
   unsigned char const* getEd25519Pk() const;

   /**
    * Get ed25519 secret key (to be used for signing)
    * @return Secret key
    */
   unsigned char const* getEd25519Sk() const;

    /**
    * Get x25519 public key (to be used for encryption)
    * @return Public key
    */
    unsigned char const* getX25519Pk() const;

    /**
     * Get x25519 secret key (to be used for encryption)
     * @return Secret key
     */
    unsigned char const* getX25519Sk() const;

   /**
    * Get ed25519 secret key as encrypted base64 string.
    * @param key SymKey to encrypt with
    * @return Encrypted base64 string
    */
   std::string sk_to_encrypted_base64(const SymKey& key);

private:
   /**
    * Generates a random ed25519 keypair.
    */
   void generate_ed25519_keypair();

   /**
    * Converts ed25519 keypair to x25519 keypair. (ed is used to sign, x is used to encrypt)
    */
   void convert_ed25519_to_x25519();

   /**
    * Read public key from base64 string.
    * @param base64_pk Base64 string
    */
   void pk_from_base64(const std::string& base64_pk);

   /**
    * Read secret key from base64 string.
    * @param base64_sk Base64 string
    */
   void sk_from_base64(const std::string& base64_sk);

   /**
    * Read secret key from encrypted base64 string.
    * @param encrypted_base64_sk Encrypted base64 string
    * @param key SymKey to decrypt with
    */
   void sk_from_encrypted_base64(const std::string& encrypted_base64_sk, const SymKey& key);
};


#endif //EFFECTIVE_OCTO_SYSTEM_EDX25519_KEYPAIR_H
