cmake_minimum_required(VERSION 3.10)
project(BlockchainNode CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Define source directories
set(CORE_DIR src/core)
set(STORAGE_DIR src/storage)
set(SMART_CONTRACTS_DIR src/smart_contracts)
set(API_DIR src/api)

# Collect all source files
file(GLOB_RECURSE SOURCES
    src/main.cpp
    src/node.cpp
    ${CORE_DIR}/*.cpp
    ${STORAGE_DIR}/*.cpp
    ${SMART_CONTRACTS_DIR}/*.cpp
    ${API_DIR}/*.cpp
)

# Add executable
add_executable(blockchain_node ${SOURCES})

# Specify include directories
target_include_directories(blockchain_node PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/${CORE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/${STORAGE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/${SMART_CONTRACTS_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/${API_DIR}
    ${OpenSSL_INCLUDE_DIR} # Include OpenSSL headers
)

# Link to OpenSSL libraries
target_link_libraries(blockchain_node PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# If using pthreads for threading (e.g., if you add NetworkManager threads)
find_package(Threads REQUIRED)
target_link_libraries(blockchain_node PRIVATE Threads::Threads)