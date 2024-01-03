cmake_minimum_required(VERSION 3.26)
project(effective-octo-system)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

set(CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
        ${CMAKE_MODULE_PATH})

find_package(Sodium REQUIRED)
find_package(nlohmann_json 3.11.3 REQUIRED)

INCLUDE_DIRECTORIES(/usr/local/include)
LINK_DIRECTORIES(/usr/local/lib)

# Libs
set(LIBS_SOURCES
        lib/CLI11.hpp
        lib/base64.cpp
        lib/base64.h
)

# Client
add_executable(eos ${LIBS_SOURCES}
        main.cpp
        Client.cpp
        Client.h
        Config.cpp
        Config.h
        Folder.cpp
        Folder.h

        web/WebClient.cpp
        web/WebClient.h
        web/WebActions.h

        crypto/Edx25519_KeyPair.cpp
        crypto/Edx25519_KeyPair.h
        crypto/SymKey.cpp
        crypto/SymKey.h
        crypto/Encryptor.cpp
        crypto/Encryptor.h
        crypto/Signator.cpp
        crypto/Signator.h
        File.cpp
        File.h
)

target_link_libraries(eos PRIVATE sodium restclient-cpp nlohmann_json::nlohmann_json)