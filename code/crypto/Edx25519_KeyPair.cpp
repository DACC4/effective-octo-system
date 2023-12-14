#include "Edx25519_KeyPair.h"
#include "Encryptor.h"

Edx25519_KeyPair::Edx25519_KeyPair()
{
    generate_ed25519_keypair();
    convert_ed25519_to_x25519();
}

Edx25519_KeyPair::Edx25519_KeyPair(const std::string& base64_sk, const std::string& base64_pk)
{
    sk_from_base64(base64_sk);
    pk_from_base64(base64_pk);
    convert_ed25519_to_x25519();
}

Edx25519_KeyPair::Edx25519_KeyPair(const std::string& encrypted_base64_sk, const std::string& base64_pk, const SymKey& key)
{
    sk_from_encrypted_base64(encrypted_base64_sk, key);
    pk_from_base64(base64_pk);
    convert_ed25519_to_x25519();
}

Edx25519_KeyPair::Edx25519_KeyPair(const std::string& base64_pk)
{
    pk_from_base64(base64_pk);
    crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
}

void Edx25519_KeyPair::generate_ed25519_keypair()
{
    crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);
}

void Edx25519_KeyPair::convert_ed25519_to_x25519()
{
    crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
    crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_skpk);
}

std::string Edx25519_KeyPair::pk_to_base64()
{
    return base64_encode(ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES);
}

std::string Edx25519_KeyPair::sk_to_base64()
{
    return base64_encode(ed25519_skpk, crypto_sign_ed25519_SECRETKEYBYTES);
}

unsigned char const* Edx25519_KeyPair::getEd25519Pk() const
{
    return ed25519_pk;
}

unsigned char const* Edx25519_KeyPair::getEd25519Sk() const
{
    return ed25519_skpk;
}

unsigned char const* Edx25519_KeyPair::getX25519Pk() const
{
    return x25519_pk;
}

unsigned char const* Edx25519_KeyPair::getX25519Sk() const
{
    return x25519_sk;
}

std::string Edx25519_KeyPair::sk_to_encrypted_base64(const SymKey& key)
{
    std::string sk = sk_to_base64();

    return base64_encode(Encryptor::encrypt(sk, key));
}

void Edx25519_KeyPair::pk_from_base64(const std::string& base64_pk)
{
    std::string tmp = base64_decode(base64_pk);
    std::copy(tmp.begin(), tmp.end(), ed25519_pk);
}

void Edx25519_KeyPair::sk_from_base64(const std::string& base64_sk)
{
    std::string tmp = base64_decode(base64_sk);
    std::copy(tmp.begin(), tmp.end(), ed25519_skpk);
}

void Edx25519_KeyPair::sk_from_encrypted_base64(const std::string& encrypted_base64_sk, const SymKey& key)
{
    std::string sk = Encryptor::decrypt(base64_decode(encrypted_base64_sk), key);
    sk_from_base64(sk);
}
