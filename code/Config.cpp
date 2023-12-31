#include "Config.h"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void Config::load(const std::string& path) {
    // Read config file and store values in this object
    try
    {
        std::ifstream f(path);
        json data = json::parse(f);

        this->server_name = data["server_name"];
        this->server_port = data["server_port"];
        this->session_token = data["session_token"];
        this->b64_sk = data["b64_sk"];
        this->username = data["username"];
    } catch (json::parse_error& e) {
        std::cout << "Failed to parse config file: " << e.what() << std::endl;
    }
}

void Config::save(const std::string& path) {
    // Write values from this object to config file
    try
    {
        json data;
        data["server_name"] = this->server_name;
        data["server_port"] = this->server_port;
        data["session_token"] = this->session_token;
        data["b64_sk"] = this->b64_sk;
        data["username"] = this->username;

        std::ofstream f(path);
        f << data.dump(4);
    } catch (json::parse_error& e) {
        std::cout << "Failed to write config file: " << e.what() << std::endl;
    }
}