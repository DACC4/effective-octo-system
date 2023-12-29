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
   std::string sign(const std::string& data, const Edx25519_KeyPair& key);

   /*
    * Verify a signature
    * @param data The data to verify
    * @param signature The signature to verify
    * @param key The key to verify with
    * @return True if the signature is valid, false otherwise
    */
   bool verify(const std::string& data, const std::string& signature, const Edx25519_KeyPair& key);
}

#endif //EFFECTIVE_OCTO_SYSTEM_SIGNATOR_H
