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

    // Save private key in base64
    Config::getInstance().setB64Sk(keyPair.sk_to_base64());
    Config::getInstance().setUsername(username);

    // Generate random root folder key
    SymKey folder_key = SymKey::random();

    // Encrypt root folder key
    std::string e_b64_key = Encryptor::encrypt(folder_key.getKeyBase64(), keyPair);

    // Create root folder if it doesn't exist
    try {
        nlohmann::json response = WebClient::getInstance().create_root_folder(folder_key.getSaltBase64(), e_b64_key);
        std::cout << "Successfully created root folder for user " << username << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to create root folder for user " << username << std::endl;
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
        response = webClient.verify_login(signature);
        std::cout << "Successfully logged in user " << username << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to login user " << username << std::endl;
    }

    // Save private key in base64
    Config::getInstance().setB64Sk(keyPair.sk_to_base64());
    Config::getInstance().setUsername(username);
}

void Client::changePassword(const std::string& newPassword)
{
    // Get private key
    std::string b64_sk = Config::getInstance().getB64Sk();

    // Get public key
    std::string b64_pk = Edx25519_KeyPair::pk_from_sk(b64_sk);

    // Get username
    std::string username = Config::getInstance().getUsername();

    // Create keypair
    Edx25519_KeyPair keyPair = Edx25519_KeyPair(b64_sk, b64_pk);

    // Create SymKey from password
    SymKey key = SymKey::deriveFromPassword(newPassword, username);

    // Get encrypted private key
    std::string encrypted_sk = keyPair.sk_to_encrypted_base64(key);

    // Hash password and encode as base64
    SymKey pKey = SymKey::deriveFromPassword(newPassword);

    // Encode password hash and salt as base64
    std::string b64_p_hash = pKey.getKeyBase64();
    std::string b64_p_salt = pKey.getSaltBase64();

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().change_password(b64_p_hash, b64_p_salt, encrypted_sk);
        std::cout << "Successfully changed password for user " << username << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to change password for user " << username << std::endl;
        return;
    }
}

void Client::logoutUser()
{
    try {
        WebClient::getInstance().logout();
    } catch (std::exception& e) {
        std::cout << "Failed to logout user " << Config::getInstance().getUsername() << std::endl;
        return;
    }

    Config::getInstance().setSessionToken("");
    Config::getInstance().setB64Sk("");
    Config::getInstance().setUsername("");
}

Folder Client::getRootFolder() {
    // Get root folder key
    nlohmann::json response;
    try {
        response = WebClient::getInstance().get_folder("/");
    } catch (std::exception& e) {
        std::cout << "Failed to get root folder key" << std::endl;
    }

    // Get encrypted root folder key and seed
    std::string e_b64_key = response["e_b64_key"];
    std::string b64_seed_k = response["b64_seed_k"];

    // Get private key
    std::string b64_sk = Config::getInstance().getB64Sk();

    // Get public key
    std::string b64_pk = Edx25519_KeyPair::pk_from_sk(b64_sk);

    // Create keypair
    Edx25519_KeyPair keyPair = Edx25519_KeyPair(b64_sk, b64_pk);

    // Decrypt root folder key
    std::string b64_key = Encryptor::decrypt(e_b64_key, keyPair);

    // Create SymKey from seed and root folder key
    SymKey key = SymKey::fromBase64(b64_key, b64_seed_k);

    return {"", "", key};
}

Folder Client::getFolderFromUserPath(const std::string& path) {
    // If user path is root, return root folder key
    if (path == "/") {
        return getRootFolder();
    }

    // If path doesn't start or end with "/", add it
    std::string tmp = path;
    if (tmp[0] != '/') {
        tmp = "/" + tmp;
    }
    if (tmp[tmp.size() - 1] != '/') {
        tmp += "/";
    }

    Folder parent = getRootFolder();
    std::string currentPath = "/";
    std::string currentEPath = "/";

    // Iterate over path
    do {
        // Get root folder contents
        nlohmann::json response;
        try {
            response = WebClient::getInstance().list_folder(currentEPath);
        } catch (std::exception& e) {
            std::cout << "Failed to get root folder contents" << std::endl;
        }

        bool found = false;

        // Iterate over root folder folders
        for (auto& [i, val] : response["folders"].items()) {
            // Get folder name and infos
            std::string e_b64_name = val["e_b64_name"];
            std::string b64_seed_n = val["b64_seed_n"];
            std::string b64_seed_k = val["b64_seed_k"];
            std::string e_b64_key = val["e_b64_key"];

            // Derive folder key from parent folder key and folder key seed
            SymKey key = SymKey::deriveFromKey(parent.getKey(), b64_seed_k);

            // Create name key from name seed and folder key
            SymKey nameKey = SymKey::fromKey(key, b64_seed_n);

            // Decrypt folder name
            std::string name = Encryptor::decrypt(e_b64_name, nameKey);

            // Folder path
            std::string folderPath = currentPath + name + "/";
            std::string folderEPath = i + "/";

            // If folder path is the one we are looking for, return encrypted folder path
            if (folderPath == tmp) {
                return {name, folderEPath, key};
            }

            // Check if the path starts with the current folder path
            if (tmp.find(folderPath) == 0) {
                // If so, set current folder as parent folder
                parent = {name, folderEPath, key};
                currentPath = folderPath;
                currentEPath = folderEPath;
                found = true;
                break;
            }
        }

        if (!found) {
            // If path is not found, throw exception
            throw std::runtime_error("Folder not found");
        }
    } while (true);
}

void Client::createFolder(const std::string& path, const std::string& name)
{
    // Get user key pair
    std::string b64_sk = Config::getInstance().getB64Sk();
    std::string b64_pk = Edx25519_KeyPair::pk_from_sk(b64_sk);
    Edx25519_KeyPair keyPair = Edx25519_KeyPair(b64_sk, b64_pk);

    // Get parent folder
    Folder parentFolder = getFolder(path);

    // Derive folder key
    SymKey key = SymKey::deriveFromKey(parentFolder.getKey());

    // Get key salt, will be used to derive folder key
    std::string b64_seed_k = key.getSaltBase64();

    // Generate new key from same key but different salt
    SymKey nameKey = SymKey::fromKey(key);

    // Encrypt folder name
    std::string e_b64_name = Encryptor::encrypt(name, nameKey);

    // Get all the data required to create the folder
    std::string b64_seed_n = nameKey.getSaltBase64();

    // Encrypt folder key
    std::string e_b64_key = Encryptor::encrypt(key.getKeyBase64(), keyPair);

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().create_folder(parentFolder.getPath(), e_b64_name, b64_seed_n, e_b64_key, b64_seed_k);
        std::cout << "Successfully created folder " << name << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to create folder " << name << std::endl;
        return;
    }
}

Folder Client::getFolder(const std::string& path)
{
    return getFolderFromUserPath(path);
}

void Client::listFolder(const std::string& path)
{
    // Get folder
    Folder tmp = getFolderFromUserPath(path);

    // List folder contents
    nlohmann::json response;
    try {
        response = WebClient::getInstance().list_folder(tmp.getPath());
    } catch (std::exception& e) {
        std::cout << "Failed to list folder contents" << std::endl;
    }

    // Iterate over folders
    std::cout << "Folders:" << std::endl;
    for (auto& [i, val] : response["folders"].items()) {
        // Get folder name and infos
        std::string e_b64_name = val["e_b64_name"];
        std::string b64_seed_n = val["b64_seed_n"];
        std::string b64_seed_k = val["b64_seed_k"];
        std::string e_b64_key = val["e_b64_key"];

        // Derive folder key from parent folder key and folder key seed
        SymKey key = SymKey::deriveFromKey(tmp.getKey(), b64_seed_k);

        // Create name key from name seed and folder key
        SymKey nameKey = SymKey::fromKey(key, b64_seed_n);

        // Decrypt folder name
        std::string name = Encryptor::decrypt(e_b64_name, nameKey);

        // Print folder name
        std::cout << "  - " << name << std::endl;
    }

    // Iterate over files
    std::cout << "Files:" << std::endl;
    for (auto& [i, val] : response["files"].items()) {
        // TODO : Decrypt file name
        std::cout << "  - " << i << std::endl;
    }
}
