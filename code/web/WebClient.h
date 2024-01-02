#ifndef EFFECTIVE_OCTO_SYSTEM_WEBCLIENT_H
#define EFFECTIVE_OCTO_SYSTEM_WEBCLIENT_H

#include <restclient-cpp/connection.h>
#include <restclient-cpp/restclient.h>
#include <nlohmann/json.hpp>
#include "WebActions.h"
#include "../Config.h"
#include "../crypto/Edx25519_KeyPair.h"

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
    * @param p_hash The password hash
    * @param p_salt The base64 encoded password salt
    * @param b64_pk The base64 encoded public key
    * @param e_b64_sk The base64 encoded encrypted private key
    * @return The response from the server
    */
   nlohmann::json register_user(const std::string& username, const std::string& p_hash, const std::string& p_salt, const std::string&
   b64_pk, const
   std::string& e_b64_sk);

    /**
     * Get the password salt of a user
     * @param username The username
     * @return The password salt
     */
   nlohmann::json get_user_password_salt(const std::string& username);

   /**
    * Get the encrypted private key of a user
    * @param username The username
    * @param passwordHash The password hash
    * @return The encrypted private key
    */
   nlohmann::json prepare_login(const std::string& username, const std::string& p_hash);

   /**
    * Login a user, will return a challenge
    * @param username The username
    * @return The response from the server containing the challenge to sign
    */
    nlohmann::json login(const std::string& username);

    /**
     * Send the signed challenge to the server
     * @param signature The signature
     * @return The response from the server
     */
    nlohmann::json verify_login(const std::string& signature);

    /**
     * Create the root folder for a user
     * @param b64_seed_k The base64 encoded folder seed
     * @param e_b64_key The base64 encoded encrypted folder key
     * @return The response from the server
     */
    nlohmann::json create_root_folder(const std::string& b64_seed_k, const std::string& e_b64_key);

    /**
     * Change the password of the current user
     * @param p_hash The password hash
     * @param p_salt The base64 encoded password salt
     * @param e_b64_sk The base64 encoded encrypted private key
     * @return The response from the server
     */
    nlohmann::json change_password(const std::string& p_hash, const std::string& p_salt, const std::string& e_b64_sk);

    /**
     * Logout the current user
     */
    void logout();

    /**
     * Get the public key of a user
     * @param username The username
     * @return The public key
     */
   nlohmann::json get_public_key(const std::string& username);

private:
   WebClient();
   ~WebClient();

   /**
    * Build a JSON body for a request
    * @param action The action to perform
    * @param body The body of the request
    * @return The JSON body
    */
   static nlohmann::json build_body(WebActions::WebAction action, const nlohmann::json& body);

public:
   WebClient(WebClient const&) = delete;
   void operator=(WebClient const&) = delete;
};


#endif //EFFECTIVE_OCTO_SYSTEM_WEBCLIENT_H
