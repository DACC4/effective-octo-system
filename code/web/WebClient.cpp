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

nlohmann::json WebClient::build_body(WebActions::WebAction action, std::string body)
{
    nlohmann::json j;
    j["request"] = WebActions::to_string(action);
    j["data"] = body;
    j["session_token"] = Config::getInstance().getSessionToken();
    return j;
}

nlohmann::json WebClient::register_user(const std::string& username, const std::string& b64_pk, const std::string& e_b64_sk)
{
    // Build body
    std::string body_str = R"({"username": ")" + username + R"(", "b64_pk": ")" + b64_pk + R"(", "e_b64_sk": ")" + e_b64_sk + "\"}";
    nlohmann::json body = build_body(WebActions::WebAction::REGISTER_USER, body_str);

    // Send request
    RestClient::Response r = conn->post(api_url, body.dump());

    // Check response code
    if (r.code != 200) {
        throw std::runtime_error("Failed to register user: " + r.body);
    }

    // Parse response
    return nlohmann::json::parse(r.body);
}