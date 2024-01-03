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

File Client::getFileFromUserPath(const std::string& path) {
    // Extract file name from path
    std::string name = path.substr(path.find_last_of('/') + 1);

    // Folder path is the path without the file name
    std::string folderPath = path.substr(0, path.find_last_of('/'));

    // Get folder
    Folder tmp = getFolderFromUserPath(folderPath);

    // List folder contents
    nlohmann::json response;
    try {
        response = WebClient::getInstance().list_folder(tmp.getPath());
    } catch (std::exception& e) {
        std::cout << "Failed to list folder contents" << std::endl;
    }

    // Iterate over files
    for (auto& [i, val] : response["files"].items()) {
        // Get file name and infos
        std::string e_b64_name = val["e_b64_name"];
        std::string b64_seed_n = val["b64_seed_n"];
        std::string b64_seed_k = val["b64_seed_k"];
        std::string b64_seed_d = val["b64_seed_d"];
        std::string e_b64_key = val["e_b64_key"];

        // Derive file key from parent folder key and file key seed
        SymKey key = SymKey::deriveFromKey(tmp.getKey(), b64_seed_k);

        // Create name key from name seed and file key
        SymKey nameKey = SymKey::fromKey(key, b64_seed_n);

        // Decrypt file name
        std::string fname = Encryptor::decrypt(e_b64_name, nameKey);

        // If file name is the one we are looking for, download it
        if (fname == name) {
            SymKey dataKey = SymKey::fromKey(key, b64_seed_d);
            return {fname, i, key, dataKey};
        }
    }

    // File not found
    throw std::runtime_error("File not found");
}

void Client::createFolder(const std::string& path)
{
    // Get file name
    std::string name = getFileName(path);

    // Get folder path
    std::string folderPath = getFolderPath(path);

    // Get user key pair
    std::string b64_sk = Config::getInstance().getB64Sk();
    std::string b64_pk = Edx25519_KeyPair::pk_from_sk(b64_sk);
    Edx25519_KeyPair keyPair = Edx25519_KeyPair(b64_sk, b64_pk);

    // Get parent folder
    Folder parentFolder = getFolderFromUserPath(folderPath);

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
        // Get file name and infos
        std::string e_b64_name = val["e_b64_name"];
        std::string b64_seed_n = val["b64_seed_n"];
        std::string b64_seed_k = val["b64_seed_k"];
        std::string e_b64_key = val["e_b64_key"];

        // Derive file key from parent folder key and file key seed
        SymKey key = SymKey::deriveFromKey(tmp.getKey(), b64_seed_k);

        // Create name key from name seed and file key
        SymKey nameKey = SymKey::fromKey(key, b64_seed_n);

        // Decrypt file name
        std::string name = Encryptor::decrypt(e_b64_name, nameKey);

        // Print file name
        std::cout << "  - " << name << std::endl;
    }
}

void Client::renameFolder(const std::string& path, const std::string& newName)
{
    // Get folder
    Folder tmp = getFolderFromUserPath(path);

    // Generate new key from same key but different salt for folder name
    SymKey newNameKey = SymKey::fromKey(tmp.getKey());

    // Encrypt folder name
    std::string e_b64_new_name = Encryptor::encrypt(newName, newNameKey);

    // Get new name key salt
    std::string b64_seed_n = newNameKey.getSaltBase64();

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().rename_folder(tmp.getPath(), e_b64_new_name, b64_seed_n);
        std::cout << "Successfully renamed folder " << tmp.getName() << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to rename folder " << tmp.getName() << std::endl;
    }
}

void Client::deleteFolder(const std::string& path)
{
    // Get folder
    Folder tmp = getFolderFromUserPath(path);

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().delete_folder(tmp.getPath());
        std::cout << "Successfully deleted folder " << tmp.getName() << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to delete folder " << tmp.getName() << std::endl;
    }
}

void Client::uploadFile(const std::string& path, const std::string& localName)
{
    // Get file name
    std::string name = getFileName(path);

    // Get folder path
    std::string folderPath = getFolderPath(path);

    // Get folder
    Folder tmp = getFolderFromUserPath(folderPath);

    // Get file contents on disk
    try {
        // Read file contents
        std::ifstream file(localName, std::ios::binary);
        std::vector<unsigned char> contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Encode file contents as base64
        std::string b64_contents = base64_encode(contents.data(), contents.size());

        // Derive file key from folder key
        SymKey key = SymKey::deriveFromKey(tmp.getKey());

        // Get file key salt
        std::string b64_seed_k = key.getSaltBase64();

        // Generate new key from same key but different salt for file name
        SymKey nameKey = SymKey::fromKey(key);

        // Encrypt file name
        std::string e_b64_name = Encryptor::encrypt(name, nameKey);
        std::string b64_seed_n = nameKey.getSaltBase64();

        // Generate new key from same key but different salt for file data
        SymKey contentsKey = SymKey::fromKey(key);

        // Encrypt file data
        std::string e_b64_data = Encryptor::encrypt(b64_contents, contentsKey);
        std::string b64_seed_d = contentsKey.getSaltBase64();

        // Get user key pair
        std::string b64_sk = Config::getInstance().getB64Sk();
        std::string b64_pk = Edx25519_KeyPair::pk_from_sk(b64_sk);
        Edx25519_KeyPair keyPair = Edx25519_KeyPair(b64_sk, b64_pk);

        // Encrypt folder key
        std::string e_b64_key = Encryptor::encrypt(key.getKeyBase64(), keyPair);

        // Send request to server
        try {
            nlohmann::json response = WebClient::getInstance().create_file(tmp.getPath(), e_b64_name, b64_seed_n, e_b64_key, b64_seed_k,
                                                                  e_b64_data, b64_seed_d);
            std::cout << "Successfully uploaded file " << name << std::endl;
        } catch (std::exception& e) {
            std::cout << "Failed to upload file " << name << std::endl;
            return;
        }

    } catch (std::exception& e) {
        std::cout << "Failed to read file " << localName << std::endl;
        return;
    }
}

void Client::downloadFile(const std::string& path)
{
    // Get file name
    std::string name = getFileName(path);

    // Get file
    File tmp = getFileFromUserPath(path);

    nlohmann::json response;
    try {
        response = WebClient::getInstance().get_file_data(tmp.getPath());
    } catch (std::exception& e) {
        std::cout << "Failed to download file " << name << std::endl;
        return;
    }

    // Get file data
    std::string e_b64_data = response["e_b64_data"];

    // Decrypt file data
    std::string b64_data = Encryptor::decrypt(e_b64_data, tmp.getDataKey());

    // Check if file already exists
    std::ifstream fcheck(name);
    if (fcheck.good()) {
        fcheck.close();
        // Remove file from disk
        std::remove(name.c_str());
    }else {
        fcheck.close();
    }

    // Write file data to disk
    std::ofstream file(name, std::ios::binary);
    std::string content = base64_decode(b64_data);
    file.write((char*)content.data(), content.size());
    file.close();

    std::cout << "Successfully downloaded file " << name << std::endl;
}

void Client::renameFile(const std::string& path, const std::string& newName)
{
    // Get file name
    std::string name = getFileName(path);

    // Get File
    File tmp = getFileFromUserPath(path);

    // Generate new key from same key but different salt for file name
    SymKey newNameKey = SymKey::fromKey(tmp.getKey());

    // Encrypt file name
    std::string e_b64_new_name = Encryptor::encrypt(newName, newNameKey);

    // Get new name key salt
    std::string b64_seed_n = newNameKey.getSaltBase64();

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().rename_file(tmp.getPath(), e_b64_new_name, b64_seed_n);
        std::cout << "Successfully renamed file " << name << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to rename file " << name << std::endl;
    }
}

void Client::deleteFile(const std::string& path)
{
    // Get file name
    std::string name = getFileName(path);

    // Get file
    File tmp = getFileFromUserPath(path);

    // Send request to server
    try {
        nlohmann::json response = WebClient::getInstance().delete_file(tmp.getPath());
        std::cout << "Successfully deleted file " << name << std::endl;
    } catch (std::exception& e) {
        std::cout << "Failed to delete file " << name << std::endl;
    }
}

std::string Client::getFileName(const std::string& path)
{
    return path.substr(path.find_last_of('/') + 1);
}

std::string Client::getFolderPath(const std::string& path)
{
    std::string tmp = path.substr(0, path.find_last_of('/'));

    if (tmp.empty())
        return "/";
    else
        return tmp;
}
