#include "Client.h"

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
    SymKey pKey = SymKey::deriveFromPassword(password);

    // Encode password hash and salt as base64
    std::string b64_p_hash = pKey.getKeyBase64();
    std::string b64_p_salt = pKey.getSaltBase64();

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().register_user(username, b64_p_hash, b64_p_salt, pk, encrypted_sk);
        std::cout << "Successfully registered user " << username << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to register user " << username << std::endl;
        return;
    }
}

void Client::loginUser(const std::string& username, const std::string& password)
{
    // Get user salt
    nlohmann::json response;
    WebClient& webClient = WebClient::getInstance();
    try {
        response = webClient.get_user_password_salt(username);
    } catch (std::exception& e) {
        std::cout << "Failed to login user " << username << std::endl;
        return;
    }

    // Get salt
    unsigned char salt[SYMKEY_SALT_SIZE];
    std::string b64_salt = response["p_salt"];
    std::string tmp = base64_decode(b64_salt);
    std::copy(tmp.begin(), tmp.end(), salt);

    // Hash password and encode as base64
    SymKey pKey = SymKey::deriveFromPassword(password, salt);

    // Get encrypted private key from server
    try {
        response = webClient.prepare_login(username, pKey.getKeyBase64());
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

    // Generate random root folder key
    SymKey folder_key = SymKey::random();

    // Encrypt root folder key
    std::string e_b64_key = base64_encode(Encryptor::encrypt(folder_key.getKeyBase64(), keyPair));

    // Create root folder if it doesn't exist
    try {
        response = webClient.create_root_folder(folder_key.getSaltBase64(), e_b64_key);
    } catch (std::exception& e) {
        std::cout << "Failed to create root folder for user " << username << std::endl;
    }
}

void Client::logoutUser(const std::string& username)
{
    WebClient::getInstance().logout(username);
}
