cmake_minimum_required(VERSION 3.10)
project(adatp_c_sdk VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)

# Library source files
set(SOURCES
    src/packet.c
    src/crypto.c
    src/client.c
)

# Create Library
add_library(adatp SHARED ${SOURCES})
target_link_libraries(adatp OpenSSL::SSL OpenSSL::Crypto)

# Example executable
add_executable(adatp_example examples/example.c)
target_link_libraries(adatp_example adatp)
