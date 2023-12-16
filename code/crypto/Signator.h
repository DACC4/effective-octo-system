#ifndef EFFECTIVE_OCTO_SYSTEM_SIGNATOR_H
#define EFFECTIVE_OCTO_SYSTEM_SIGNATOR_H

#include <string>
#include <sodium.h>
#include "../lib/base64.h"
#include "Edx25519_KeyPair.h"

namespace Signator
{
   /*
    * Sign a string with the given public key
    * @param data The data to sign
    * @param key The key to sign with
    * @return The signature as a base64 encoded string
    */
   std::string sign(const std::string& data, const Edx25519_KeyPair& key)
   {
       unsigned char sig[crypto_sign_BYTES];

       // Sign data
       crypto_sign_detached(sig, NULL,
                            reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
                            key.getEd25519Sk());

       // Encode signature
       return base64_encode(sig, crypto_sign_BYTES);
   }

   /*
    * Verify a signature
    * @param data The data to verify
    * @param signature The signature to verify
    * @param key The key to verify with
    * @return True if the signature is valid, false otherwise
    */
   bool verify(const std::string& data, const std::string& signature, const Edx25519_KeyPair& key)
   {
       // Decode signature
       unsigned char sig[crypto_sign_BYTES];
       std::string tmp = base64_decode(signature);
       std::copy(tmp.begin(), tmp.end(), sig);

       // Verify signature
       return (crypto_sign_verify_detached(sig,
                                       reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
                                       key.getEd25519Pk()) == 0);
   }
}

#endif //EFFECTIVE_OCTO_SYSTEM_SIGNATOR_H
