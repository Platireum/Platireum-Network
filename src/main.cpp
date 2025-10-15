#include <iostream>
#include <string>
#include <memory> // For std::shared_ptr
#include <random> // For unique node IDs
#include <chrono> // For timestamps

// Include all core components
#include "node.h"
#include "core/key_generator.h" // To generate keys for nodes/users
#include "api/api_server.h"
#include "api/cli_client.h"
#include "utils/id_generator.h" // For generateUniqueId

int main() {
    std::cout << "Starting Blockchain Node Application..." << std::endl;

    // --- 1. Generate Keys for the Node ---
    CryptoHelper::ECKeyPtr nodePrivateKeyEC = CryptoHelper::generateKeyPair();
    std::string nodePubKey = CryptoHelper::getPublicKeyHex(nodePrivateKeyEC);
    std::string nodeId = generateUniqueId("node"); // Generate a unique ID for the node

    std::cout << "\nNode Identity Generated:" << std::endl;
    std::cout << "  ID: " << nodeId.substr(0, 16) << "..." << std::endl;
    std::cout << "  Public Key: " << nodePubKey.substr(0, 20) << "..." << std::endl;

    // --- 2. Create and Initialize the Blockchain Node ---
    std::shared_ptr<Node> blockchainNode = std::make_shared<Node>(nodeId, nodePubKey, nodePrivateKeyEC);
    try {
        blockchainNode->initialize();
        blockchainNode->start();
    } catch (const std::runtime_error& e) {
        std::cerr << "Node initialization failed: " << e.what() << std::endl;
        return 1; // Exit on critical error
    }

    // --- 3. Create and Initialize the API Server ---
    // The API server will listen on a specific address and port
    std::string apiAddress = "127.0.0.1"; // Localhost
    int apiPort = 8080;
    std::shared_ptr<ApiServer> apiServer = std::make_shared<ApiServer>(apiAddress, apiPort, blockchainNode);
    try {
        apiServer->initialize();
        apiServer->start();
    } catch (const ApiServerError& e) {
        std::cerr << "API Server initialization failed: " << e.what() << std::endl;
        return 1; // Exit on critical error
    }

    // --- 4. Create and Start the CLI Client ---
    // The CLI client will interact with the API server
    std::shared_ptr<CliClient> cliClient = std::make_shared<CliClient>(apiServer, nodePubKey);
    
    // Start the CLI command loop
    std::cout << "\nBlockchain CLI is ready. Type 'help' for commands." << std::endl;
    cliClient->start(); // This call will block until 'exit' command is given

    // --- 5. Cleanup (after CLI exits) ---
    apiServer->stop();
    // In a real application, you might want to save the node's state
    // before shutting down, though StorageManager handles much of this.
    std::cout << "Blockchain Node Application stopped." << std::endl;

    return 0;
}

