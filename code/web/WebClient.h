#ifndef EFFECTIVE_OCTO_SYSTEM_WEBCLIENT_H
#define EFFECTIVE_OCTO_SYSTEM_WEBCLIENT_H

#include <restclient-cpp/connection.h>
#include <restclient-cpp/restclient.h>
#include <nlohmann/json.hpp>
#include "WebActions.h"
#include "../Config.h"

class WebClient
{
   RestClient::Connection* conn;
   std::string api_url = "/api";

public:
   /**
    * Get the singleton instance of the WebClient
    * @return The WebClient instance
    */
   static WebClient& getInstance();

   /**
    * Register a new user
    * @param username The username
    * @param b64_pk The base64 encoded public key
    * @param e_b64_sk The base64 encoded encrypted private key
    * @return The response from the server
    */
   nlohmann::json register_user(const std::string& username, const std::string& b64_pk, const std::string& e_b64_sk);

private:
   WebClient();
   ~WebClient();

   /**
    * Build a JSON body for a request
    * @param action The action to perform
    * @param body The body of the request
    * @return The JSON body
    */
   static nlohmann::json build_body(WebActions::WebAction action, std::string body);

public:
   WebClient(WebClient const&) = delete;
   void operator=(WebClient const&) = delete;
};


#endif //EFFECTIVE_OCTO_SYSTEM_WEBCLIENT_H
