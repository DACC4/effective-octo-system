cmake_minimum_required(VERSION 3.26)
project(effective-octo-system)

set(CLIENT_PROJECT_NAME ${PROJECT_NAME}-client)
set(SERVER_PROJECT_NAME ${PROJECT_NAME}-server)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -Werror")

set(CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
        ${CMAKE_MODULE_PATH})

find_package(Sodium REQUIRED)

# Common
set(COMMON_SOURCES
        lib/CLI11.hpp
)

# Client
add_executable(${CLIENT_PROJECT_NAME} ${COMMON_SOURCES}
        client/main.cpp

target_link_libraries(${CLIENT_PROJECT_NAME} PRIVATE sodium)

# Server
add_executable(${SERVER_PROJECT_NAME} ${COMMON_SOURCES}
        server/main.cpp)

target_link_libraries(${SERVER_PROJECT_NAME} PRIVATE sodium)