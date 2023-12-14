#ifndef EFFECTIVE_OCTO_SYSTEM_CONFIG_H
#define EFFECTIVE_OCTO_SYSTEM_CONFIG_H

#include <string>

class Config
{
    std::string server_name;
    unsigned server_port;
    std::string session_token;

private:
    Config() {
        server_name = "";
        server_port = 0;
        session_token = "";
    }

public:
   Config(const Config&) = delete;
   Config& operator=(const Config&) = delete;
    ~Config() = default;

    static Config& getInstance() {
        static Config instance;

        return instance;
    }

    std::string getServerName() const {
        return server_name;
    }
    unsigned getServerPort() const {
        return server_port;
    }
    std::string getSessionToken() const {
        return session_token;
    }

    void setServerName(const std::string& server_name) {
        this->server_name = server_name;
    }

    void setServerPort(const unsigned& server_port) {
        this->server_port = server_port;
    }

    void setSessionToken(const std::string& session_token) {
        this->session_token = session_token;
    }

    void save(const std::string& path);
    void load(const std::string& path);
};


#endif //EFFECTIVE_OCTO_SYSTEM_CONFIG_H
