#include <iostream>
#include <sodium.h>
#include "lib/CLI11.hpp"
#include "Client.h"
#include "Config.h"
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

int main(int argc, char** argv)
{
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cout << "sodium_init() failed" << std::endl;
        return 1;
    }

    const string config_path = "config.json";
    const string default_server_name = "localhost";
    const unsigned default_server_port = 4242;

    // Use CLI11 to parse command line arguments
    CLI::App app{"Effective Octo System Client"};

    // Here's the list of verbs available to the user
    /*
     * config <server_name> <server_port>
     * register <username> <password>
     * login <username> <password>
     * logout
     * upload <path> <file>
     * download <path> <file>
     * delete <path> (<file>)
     * rename_file <file_path> <new_name>
     * create_folder <path>
     * delete_folder <path>
     * rename_folder <folder_path> <new_name>
     * list <path>
     * share <path> <username>
     * revoke <path> <username>
     * list_shares <path>
     * list_shared_with_me
     */

    // Config
    CLI::App* config = app.add_subcommand("config", "Configure the server to connect to and display config");
    std::string config_server_name;
    unsigned config_server_port;
    config->add_option("server_name", config_server_name, "Server name");
    config->add_option("server_port", config_server_port, "Server port");

    // Register
    CLI::App* register_ = app.add_subcommand("register", "Register a new user");
    std::string regsiter_username;
    std::string regsiter_password;
    register_->add_option("username", regsiter_username, "Username")->required();
    register_->add_option("password", regsiter_password, "Password")->required();

    // Login
    CLI::App* login = app.add_subcommand("login", "Login to the server");
    std::string login_username;
    std::string login_password;
    login->add_option("username", login_username, "Username")->required();
    login->add_option("password", login_password, "Password")->required();

    // Change password
    CLI::App* change_password = app.add_subcommand("change_password", "Change the password of the current user");
    std::string change_password_new_password;
    change_password->add_option("new_password", change_password_new_password, "New password")->required();

    // Logout
    CLI::App* logout = app.add_subcommand("logout", "Logout from the server");

    // Upload
    CLI::App* upload = app.add_subcommand("upload", "Upload a file to the server");
    std::string upload_path;
    std::string upload_file;
    upload->add_option("file", upload_file, "Local file to upload")->required();
    upload->add_option("path", upload_path, "File path on the server")->required();

    // Download
    CLI::App* download = app.add_subcommand("download", "Download a file from the server");
    std::string download_path;
    download->add_option("path", download_path, "File path")->required();

    // Delete
    CLI::App* delete_ = app.add_subcommand("delete", "Delete a file from the server");
    std::string delete_path;
    delete_->add_option("path", delete_path, "Path of the file to delete")->required();

    // Rename file
    CLI::App* rename_file = app.add_subcommand("rename_file", "Rename a file on the server");
    std::string rename_file_path;
    std::string rename_file_new_name;
    rename_file->add_option("path", rename_file_path, "Path of the file to rename")->required();
    rename_file->add_option("new_name", rename_file_new_name, "New name of the file")->required();

    // Create folder
    CLI::App* create_folder = app.add_subcommand("create_folder", "Create a folder on the server");
    std::string create_folder_path;
    create_folder->add_option("path", create_folder_path, "Folder to create")->required();

    // Delete folder
    CLI::App* delete_folder = app.add_subcommand("delete_folder", "Delete a folder from the server");
    std::string delete_folder_path;
    delete_folder->add_option("path", delete_folder_path, "Folder to delete")->required();

    // Rename folder
    CLI::App* rename_folder = app.add_subcommand("rename_folder", "Rename a folder on the server");
    std::string rename_folder_path;
    std::string rename_folder_new_name;
    rename_folder->add_option("path", rename_folder_path, "Folder in which the folder is")->required();
    rename_folder->add_option("new_name", rename_folder_new_name, "New name of the folder")->required();

    // List
    CLI::App* list = app.add_subcommand("list", "List the content of a folder on the server");
    std::string list_path;
    list->add_option("path", list_path, "Folder to list")->required();

    // Share
    CLI::App* share = app.add_subcommand("share", "Share a file or folder with another user");
    std::string share_path;
    std::string share_file;
    std::string share_username;
    share->add_option("path", share_path, "Folder in which the file is or folder to share if no file is specified")->required();
    share->add_option("file", share_file, "File to share");
    share->add_option("username", share_username, "User to share the file with")->required();

    // Revoke
    CLI::App* revoke = app.add_subcommand("revoke", "Revoke a user's access to a file or folder");
    std::string revoke_path;
    std::string revoke_file;
    std::string revoke_username;
    revoke->add_option("path", revoke_path, "Folder in which the file is or folder to revoke access to if no file is specified")->required();
    revoke->add_option("file", revoke_file, "File to revoke access to");
    revoke->add_option("username", revoke_username, "User to revoke access to the file from")->required();

    // List shares
    CLI::App* list_shares = app.add_subcommand("list_shares", "List the users a file or folder is shared with");
    std::string list_shares_path;
    std::string list_shares_file;
    list_shares->add_option("path", list_shares_path, "Folder in which the file is or file to list shares of if no file is specified")->required();
    list_shares->add_option("file", list_shares_file, "File to list shares of");

    // List shared with me
    CLI::App* list_shared_with_me = app.add_subcommand("list_shared_with_me", "List the files and folders shared with me");

    // Parse command line arguments
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    // Check if the config file exists
    ifstream config_file(config_path);
    if (!config_file.good()) {
        // If it doesn't, create it
        json config_json;
        config_json["server_name"] = default_server_name;
        config_json["server_port"] = default_server_port;
        config_json["session_token"] = "";
        config_json["b64_sk"] = "";
        config_json["username"] = "";
        ofstream config_file_o(config_path);
        config_file_o << config_json.dump(4);
        config_file_o.close();
    }

    // Load the config file
    Config& app_config = Config::getInstance();
    app_config.load(config_path);

    // If no verb is specified, print help
    if (app.get_subcommands().empty()) {
        std::cout << app.help() << std::endl;
        return 0;
    }

    // Initialize the client
    Client client = Client();

    // Link verbs to their respective functions
    if (config->parsed()) {
        // Get current values if none are specified
        if (config_server_name.empty())
            config_server_name = app_config.getServerName();
        if (config_server_port == 0)
            config_server_port = app_config.getServerPort();

        // Update config
        app_config.setServerName(config_server_name);
        app_config.setServerPort(config_server_port);
        app_config.save(config_path);

        // Print config
        std::cout << "Server name: " << app_config.getServerName() << std::endl;
        std::cout << "Server port: " << app_config.getServerPort() << std::endl;
    } else if (register_->parsed()) {
        client.registerUser(regsiter_username, regsiter_password);
    } else if (login->parsed()) {
        client.loginUser(login_username, login_password);
    } else if (change_password->parsed()) {
        client.changePassword(change_password_new_password);
    } else if (logout->parsed()) {
        client.logoutUser();
    } else if (upload->parsed()) {
        client.uploadFile(upload_path, upload_file);
    } else if (download->parsed()) {
        client.downloadFile(download_path);
    } else if (delete_->parsed()) {
        client.deleteFile(delete_path);
    } else if (rename_file->parsed()) {
        client.renameFile(rename_file_path, rename_file_new_name);
    } else if (create_folder->parsed()) {
        client.createFolder(create_folder_path);
    } else if (delete_folder->parsed()) {
        client.deleteFolder(delete_folder_path);
    } else if (rename_folder->parsed()) {
        client.renameFolder(rename_folder_path, rename_folder_new_name);
    } else if (list->parsed()) {
        client.listFolder(list_path);
    } else if (share->parsed()) {
        std::cout << "share" << std::endl;
    } else if (revoke->parsed()) {
        std::cout << "revoke" << std::endl;
    } else if (list_shares->parsed()) {
        std::cout << "list_shares" << std::endl;
    } else if (list_shared_with_me->parsed()) {
        std::cout << "list_shared_with_me" << std::endl;
    }

    // Write config file
    app_config.save(config_path);

    return 0;
}
