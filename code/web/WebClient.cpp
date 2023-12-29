#include "WebClient.h"

WebClient& WebClient::getInstance()
{
    static WebClient instance;
    return instance;
}

WebClient::WebClient()
{
    RestClient::init();

    // TODO: Change for HTTPS
    conn = new RestClient::Connection(
       "http://" +
       Config::getInstance().getServerName() +
       ":" +
       std::to_string(Config::getInstance().getServerPort()));

    conn->SetTimeout(5);
    conn->SetUserAgent("effective-octo-system-client/0.1");
    RestClient::HeaderFields headers;
    headers["Content-Type"] = "application/json";
    headers["Accept"] = "application/json";
    conn->SetHeaders(headers);
}

WebClient::~WebClient()
{
    RestClient::disable();
    delete conn;
}

nlohmann::json WebClient::build_body(WebActions::WebAction action, const nlohmann::json& body)
{
    nlohmann::json j;
    j["request"] = WebActions::to_string(action);
    j["session_token"] = Config::getInstance().getSessionToken();

    if (!body.empty()) {
        j += {"data", body};
    }

    return j;
}

nlohmann::json WebClient::register_user(const std::string& username, const std::string& p_hash, const std::string& p_salt, const std::string& b64_pk, const
std::string&
e_b64_sk)
{
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["username"] = username;
    d_body["p_hash"] = p_hash;
    d_body["p_salt"] = p_salt;
    d_body["b64_pk"] = b64_pk;
    d_body["e_b64_sk"] = e_b64_sk;
    nlohmann::json body = build_body(WebActions::WebAction::REGISTER_USER, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to register user: " + r.body);
    }

    // Parse response
    return nlohmann::json::parse(r.body);
}

nlohmann::json WebClient::get_user_password_salt(const std::string& username) {
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["username"] = username;
    nlohmann::json body = build_body(WebActions::WebAction::GET_USER_PASSWORD_SALT, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to get user salt: " + r.body);
    }

    // Parse response
    return nlohmann::json::parse(r.body);
}

nlohmann::json WebClient::prepare_login(const std::string& username, const std::string& p_hash) {
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["username"] = username;
    d_body["p_hash"] = p_hash;
    nlohmann::json body = build_body(WebActions::WebAction::PREPARE_LOGIN, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to get user esk: " + r.body);
    }

    // Parse response
    return nlohmann::json::parse(r.body);
}

nlohmann::json WebClient::login(const std::string& username) {
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["username"] = username;
    nlohmann::json body = build_body(WebActions::WebAction::LOGIN, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to login: " + r.body);
    }

    // Parse response
    nlohmann::json response = nlohmann::json::parse(r.body);

    // Store session token
    Config::getInstance().setSessionToken(response["session_token"]);

    return response;
}

nlohmann::json WebClient::verify_login(const std::string& username, const std::string& signature) {
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["username"] = username;
    d_body["signature"] = signature;
    nlohmann::json body = build_body(WebActions::WebAction::VERIFY_LOGIN, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to send challenge: " + r.body);
    }

    // Parse response
    nlohmann::json response = nlohmann::json::parse(r.body);

    // Store session token
    Config::getInstance().setSessionToken(response["session_token"]);

    return response;
}

nlohmann::json WebClient::create_root_folder(const std::string& seed, const std::string& e_b64_key) {
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["seed"] = seed;
    d_body["e_b64_key"] = e_b64_key;
    nlohmann::json body = build_body(WebActions::WebAction::CREATE_ROOT_FOLDER, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to create root folder: " + r.body);
    }

    // Parse response
    return nlohmann::json::parse(r.body);
}

void WebClient::logout(const std::string& username) {
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["username"] = username;
    nlohmann::json body = build_body(WebActions::WebAction::LOGOUT, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to logout: " + r.body);
    }
}

nlohmann::json WebClient::get_public_key(const std::string& username){
    // Build body
    nlohmann::json d_body = nlohmann::json();
    d_body["username"] = username;
    nlohmann::json body = build_body(WebActions::WebAction::GET_USER_PUBLIC_KEY, d_body);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to get user pk: " + r.body);
    }

    // Parse response
    return nlohmann::json::parse(r.body);
}