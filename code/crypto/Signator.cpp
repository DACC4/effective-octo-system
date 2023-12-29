#include "Signator.h"

namespace Signator
{
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