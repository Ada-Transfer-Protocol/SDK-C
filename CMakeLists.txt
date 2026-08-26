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
    src/ws.c
    src/client.c
)

# Create Library
add_library(adatp SHARED ${SOURCES})
target_link_libraries(adatp OpenSSL::SSL OpenSSL::Crypto)

# Example executable
add_executable(adatp_example examples/example.c)
target_link_libraries(adatp_example adatp)

# --- Tests ---
enable_testing()

# v2 handshake conformance (golden-vector replay; no server needed).
add_executable(conformance_v2 test/conformance_v2.c)
target_link_libraries(conformance_v2 adatp)
add_test(NAME conformance_v2 COMMAND conformance_v2)

# v2 end-to-end client (used by test/run_e2e_v2.sh against a live Rust server).
add_executable(e2e_v2 test/e2e_v2.c)
target_link_libraries(e2e_v2 adatp)
