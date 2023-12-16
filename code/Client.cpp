#include "Client.h"

#include "crypto/Edx25519_KeyPair.h"
#include "web/WebClient.h"
#include "crypto/Signator.h"

#include <nlohmann/json.hpp>
#include <iostream>

void Client::registerUser(const std::string& username, const std::string& password)
{
    // Generate keypair
    Edx25519_KeyPair keyPair = Edx25519_KeyPair();

    // Create SymKey from password
    SymKey key = SymKey::deriveFromPassword(password, username);

    // Get encrypted private key
    std::string encrypted_sk = keyPair.sk_to_encrypted_base64(key);

    // Get public key
    std::string pk = keyPair.pk_to_base64();

    // Hash password and encode as base64
    unsigned char p_hash[PASSWORD_HASH_LENGTH];
    crypto_generichash(p_hash, sizeof p_hash,
                       (const unsigned char*)password.c_str(), password.size(),
                       nullptr, 0);
    std::string b64_p_hash = base64_encode(p_hash, PASSWORD_HASH_LENGTH);

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().register_user(username, b64_p_hash, pk, encrypted_sk);
        std::cout << "Successfully registered user " << username << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to register user " << username << std::endl;
    }
}

void Client::loginUser(const std::string& username, const std::string& password)
{
    // Hash password and encode as base64
    unsigned char p_hash[PASSWORD_HASH_LENGTH];
    crypto_generichash(p_hash, sizeof p_hash,
                       (const unsigned char*)password.c_str(), password.size(),
                       nullptr, 0);
    std::string b64_p_hash = base64_encode(p_hash, PASSWORD_HASH_LENGTH);

    // Get encrypted private key from server
    nlohmann::json response;
    WebClient& webClient = WebClient::getInstance();
    try {
        response = webClient.prepare_login(username, b64_p_hash);
    } catch (std::exception& e) {
        std::cout << "Failed to login user " << username << std::endl;
        return;
    }

    // Get encrypted private key
    std::string encrypted_sk = response["e_b64_sk"];

    // Get public key
    response = webClient.get_public_key(username);
    std::string pk = response["b64_pk"];

    // Decrypt private key
    SymKey key = SymKey::deriveFromPassword(password, username);
    Edx25519_KeyPair keyPair = Edx25519_KeyPair(encrypted_sk, pk, key);

    // Ask for challenge
    try {
        response = webClient.login(username);
    } catch (std::exception& e) {
        std::cout << "Failed to login user " << username << std::endl;
        return;
    }
    std::string challenge = response["challenge"];

    // Sign challenge
    std::string signature = Signator::sign(challenge, keyPair);

    // Send signed challenge
    try {
        response = webClient.verify_login(username, signature);
        std::cout << "Successfully logged in user " << username << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to login user " << username << std::endl;
    }
}

void Client::logoutUser(const std::string& username)
{
    WebClient::getInstance().logout(username);
}
