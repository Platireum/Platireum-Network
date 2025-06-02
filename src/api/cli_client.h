#ifndef CLI_CLIENT_H
#define CLI_CLIENT_H

#include <string>
#include <memory>         // For std::shared_ptr
#include <vector>         // For command arguments
#include <stdexcept>      // For custom exceptions
#include <iostream>       // For input/output

// Include the ApiServer header as CLIClient will interact with it
#include "api_server.h"

// Forward declare Wallet or KeyGenerator if CLI needs to create/manage keys
// class Wallet;
// class KeyGenerator;

// --- 0. Error Handling ---
/**
 * @brief Custom exception class for CLI Client-specific errors.
 */
class CliClientError : public std::runtime_error {
public:
    explicit CliClientError(const std::string& msg) : std::runtime_error(msg) {}
};

// --- 1. CLI Client Class ---
/**
 * @brief A simplified Command Line Interface (CLI) client for interacting with the blockchain API.
 *
 * This client takes user input from the console, constructs API requests,
 * sends them to an ApiServer, and displays the responses.
 * It acts as a user-friendly frontend to the blockchain node.
 */
class CliClient {
private:
    std::shared_ptr<ApiServer> apiServer; // The API server this client will communicate with
    std::string defaultSenderId; // Default sender for transactions/contract calls (e.g., node's own ID)

    void log(const std::string& message) const;
    void displayResponse(const ApiResponse& response) const;

    // --- Command Handling Methods ---
    // These methods parse CLI arguments and construct ApiRequest objects
    // then send them via apiServer->processRequest().

    /**
     * @brief Handles the 'info' command to get node information.
     * Usage: info
     */
    void handleInfoCommand();

    /**
     * @brief Handles the 'sendtx' command to create and send a transaction.
     * Usage: sendtx <recipient_id> <amount> [message]
     */
    void handleSendTxCommand(const std::vector<std::string>& args);

    /**
     * @brief Handles the 'getblock' command to retrieve a block by hash.
     * Usage: getblock <block_hash>
     */
    void handleGetBlockCommand(const std::vector<std::string>& args);
    
    /**
     * @brief Handles the 'balance' command to check an account balance.
     * Usage: balance <account_id>
     */
    void handleBalanceCommand(const std::vector<std::string>& args);

    /**
     * @brief Handles the 'mine' command to trigger block mining (for testing).
     * Usage: mine
     */
    void handleMineCommand(); // For simulation/testing purposes

    /**
     * @brief Handles the 'deploycontract' command to deploy a new smart contract.
     * Usage: deploycontract <contract_code> <owner_public_key> [initial_state_json]
     */
    void handleDeployContractCommand(const std::vector<std::string>& args);

    /**
     * @brief Handles the 'callcontract' command to execute a method on a smart contract.
     * Usage: callcontract <contract_id> <method_name> [params_json] [sender_id]
     */
    void handleCallContractCommand(const std::vector<std::string>& args);

    /**
     * @brief Displays the available commands and their usage.
     */
    void displayHelp() const;

public:
    /**
     * @brief Constructor for CliClient.
     * @param apiSrv The shared_ptr to the ApiServer instance this client will communicate with.
     * @param senderId The default public key to use as the sender for transactions.
     */
    CliClient(std::shared_ptr<ApiServer> apiSrv, const std::string& senderId);

    /**
     * @brief Starts the CLI client, entering a command loop.
     * This function will continuously read commands from the user until 'exit' is typed.
     */
    void start();

    /**
     * @brief Parses a command string into a vector of arguments.
     * @param commandLine The full command string from the user.
     * @return A vector of strings, where the first element is the command name
     * and subsequent elements are its arguments.
     */
    static std::vector<std::string> parseCommand(const std::string& commandLine);
};

#endif // CLI_CLIENT_H