#ifndef EFFECTIVE_OCTO_SYSTEM_WEBACTIONS_H
#define EFFECTIVE_OCTO_SYSTEM_WEBACTIONS_H

#include <string>

namespace WebActions
{
   enum WebAction
   {
      REGISTER_USER,
      GET_USER_PASSWORD_SALT,
      PREPARE_LOGIN,
      LOGIN,
      VERIFY_LOGIN,
      CREATE_ROOT_FOLDER,
      REGISTER,
      LOGOUT,
      GET_USERS,
      GET_USER_PUBLIC_KEY,
      CHANGE_PASSWORD,
      CREATE_FOLDER,
      CREATE_FILE,
      GET_FILE,
      GET_FOLDER,
      UPDATE_FILE,
      UPDATE_FOLDER,
      SHARE_FOLDER,
      SHARE_FILE,
      REVOKE_FOLDER,
      REVOKE_FILE
   };

   static const char* WebActionStrings[] = {
      "REGISTER_USER",
      "GET_USER_PASSWORD_SALT",
      "PREPARE_LOGIN",
      "LOGIN",
      "VERIFY_LOGIN",
      "CREATE_ROOT_FOLDER",
      "REGISTER",
      "LOGOUT",
      "GET_USERS",
      "GET_USER_PUBLIC_KEY",
      "CHANGE_PASSWORD",
      "CREATE_FOLDER",
      "CREATE_FILE",
      "GET_FILE",
      "GET_FOLDER",
      "UPDATE_FILE",
      "UPDATE_FOLDER",
      "SHARE_FOLDER",
      "SHARE_FILE",
      "REVOKE_FOLDER",
      "REVOKE_FILE"
   };

   static WebAction getWebActionFromString(const std::string& str)
   {
       for (unsigned i = 0; i < (sizeof(WebActionStrings) / sizeof(WebActionStrings[0])); i++)
       {
           if (str == WebActionStrings[i])
           {
               return static_cast<WebAction>(i);
           }
       }
       return PREPARE_LOGIN;
   }

   static std::string to_string(const WebAction& action)
   {
       return WebActionStrings[action];
   }
}

#endif //EFFECTIVE_OCTO_SYSTEM_WEBACTIONS_H
