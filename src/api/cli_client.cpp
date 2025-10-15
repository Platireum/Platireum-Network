#include "cli_client.h"
#include <sstream> // For std::stringstream
#include <ctime> // For std::time
#include <chrono> // For std::chrono
#include "../../src/smart_contracts/contract.h" // For SmartContract class
#include "../../src/utils/json_utils.h" // For JSON utility functions
#include <algorithm> // For std::remove
#include <limits>    // For std::numeric_limits

// --- Helper for creating simple JSON strings (for request bodies) ---
// This is a very rudimentary JSON builder. In a real-world scenario,
// use a robust JSON library like nlohmann/json.


// Constructor
CliClient::CliClient(std::shared_ptr<ApiServer> apiSrv, const std::string& senderId)
    : apiServer(apiSrv), defaultSenderId(senderId) {
    if (!apiServer) {
        throw CliClientError("CliClient initialized with a null ApiServer instance.");
    }
    log("CLI Client initialized. Default sender: " + defaultSenderId);
}

// Simple logging utility
void CliClient::log(const std::string& message) const {
    std::cout << "[CLI Client] " << message << std::endl;
}

// Displays API response to the user
void CliClient::displayResponse(const ApiResponse& response) const {
    if (response.statusCode >= 200 && response.statusCode < 300) {
        std::cout << "SUCCESS (" << response.statusCode << "): " << response.body << std::endl;
    } else {
        std::cout << "ERROR (" << response.statusCode << "): " << response.error << std::endl;
    }
}

// --- Command Handling Implementations ---

void CliClient::handleInfoCommand() {
    ApiRequest request("/node/info", "GET");
    ApiResponse response = apiServer->processRequest(request);
    displayResponse(response);
}

void CliClient::handleSendTxCommand(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << "Usage: sendtx <recipient_id> <amount> [message]" << std::endl;
        return;
    }
    std::string recipient = args[1];
    double amount = std::stod(args[2]);
    std::string message = (args.size() > 3) ? args[3] : "";

    // Create a dummy transaction for the API.
    // In a real scenario, this would involve key signing.
    // Here, we simulate a simple value transfer transaction.
    // We're creating a Transaction object here. It would ideally be signed.
    // For now, we'll use a placeholder for `id` and `signature`.
    // The `ApiServer` will just broadcast it.
    std::string txId = "tx_" + std::to_string(std::hash<std::string>{}(recipient + std::to_string(amount) + message + defaultSenderId)); // Simple hash
    std::string timestamp = std::to_string(std::time(nullptr));

    std::unordered_map<std::string, std::string> tx_details;
    tx_details["id"] = txId;
    tx_details["sender"] = defaultSenderId;
    tx_details["recipient"] = recipient;
    tx_details["amount"] = std::to_string(amount);
    tx_details["message"] = message;
    tx_details["timestamp"] = timestamp;
    tx_details["type"] = "VALUE_TRANSFER"; // Explicitly setting type
    tx_details["signature"] = "dummy_signature"; // Placeholder

    ApiRequest request("/transaction", "POST", createSimpleJson(tx_details));
    ApiResponse response = apiServer->processRequest(request);
    displayResponse(response);
}

void CliClient::handleGetBlockCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Usage: getblock <block_hash>" << std::endl;
        return;
    }
    std::string blockHash = args[1];
    ApiRequest request("/block/" + blockHash, "GET"); // Use path parameter
    ApiResponse response = apiServer->processRequest(request);
    displayResponse(response);
}

void CliClient::handleBalanceCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Usage: balance <account_id>" << std::endl;
        return;
    }
    std::string accountId = args[1];
    // In a real system, you might have a dedicated API endpoint like /account/{id}/balance
    // For now, we can try to "fake" it by calling a contract or getting node info
    // For simplicity, let's assume node info can provide balance (will need Node.getAccountBalance())
    // A better approach is to have a dedicated endpoint for this.
    // For now, we'll try to get it from a generic blockchain state endpoint if possible or a contract.
    // A direct call from Node might be easier if Node has a getAccountBalance method.
    
    // As a workaround, let's just query a simplified smart contract for balances for now,
    // assuming there's a TokenContract and a balanceOf method.
    // This is a simplification; a direct blockchain balance query would be separate.

    std::unordered_map<std::string, std::string> call_params;
    call_params["contract_id"] = "token_contract_id_placeholder"; // Replace with actual token contract ID
    call_params["sender_id"] = defaultSenderId;
    call_params["method_name"] = "balanceOf";
    call_params["params_json"] = createSimpleJson({{"account", accountId}});

    ApiRequest request("/contract/call", "POST", createSimpleJson(call_params));
    ApiResponse response = apiServer->processRequest(request);
    displayResponse(response);
}


void CliClient::handleMineCommand() {
    ApiRequest request("/mine", "POST");
    ApiResponse response = apiServer->processRequest(request);
    displayResponse(response);
}

void CliClient::handleDeployContractCommand(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << "Usage: deploycontract <contract_code> <owner_public_key> [initial_state_json]" << std::endl;
        std::cout << "  Example: deploycontract TokenContract " << defaultSenderId << " {\"name\":\"MyToken\"}" << std::endl;
        return;
    }
    std::string contractCode = args[1];
    std::string ownerPublicKey = args[2];
    std::string initialStateJson = (args.size() > 3) ? args[3] : "{}";

    // Create a dummy SmartContract object for serialization
    // In a real scenario, contractId might be derived from transaction hash
    std::string contractId = "contract_" + std::to_string(std::hash<std::string>{}(contractCode + ownerPublicKey + initialStateJson));
    
    // For now, SmartContract::deserialize expects a specific format for state.
    // We need to build a full contract JSON then deserialize it,
    // or improve SmartContract::deserialize to take individual fields.
    // Let's create a temporary SmartContract and serialize it.
    SmartContract tempContract(contractId, std::vector<uint8_t>(contractCode.begin(), contractCode.end()), ownerPublicKey);
    
    // If initialStateJson is provided, attempt to parse and set it.
    // This requires a simple JSON parser for the initial state.
    auto initial_state_map = parseSimpleJson(initialStateJson);
    for (const auto& pair : initial_state_map) {
        tempContract.setState(pair.first, pair.second);
    }
    
    std::string serializedContract = tempContract.serialize();

    ApiRequest request("/contract/deploy", "POST", serializedContract);
    ApiResponse response = apiServer->processRequest(request);
    displayResponse(response);
}

void CliClient::handleCallContractCommand(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        std::cout << "Usage: callcontract <contract_id> <method_name> [params_json] [sender_id]" << std::endl;
        std::cout << "  Example: callcontract contract_abc123 transfer '{\"from\":\"addr1\",\"to\":\"addr2\",\"amount\":\"100\"}'" << std::endl;
        return;
    }
    std::string contractId = args[1];
    std::string methodName = args[2];
    std::string paramsJson = (args.size() > 3) ? args[3] : "{}";
    std::string senderId = (args.size() > 4) ? args[4] : defaultSenderId;

    std::unordered_map<std::string, std::string> call_params_map;
    call_params_map["contract_id"] = contractId;
    call_params_map["sender_id"] = senderId;
    call_params_map["method_name"] = methodName;
    call_params_map["params_json"] = paramsJson; // Pass params_json as a string

    ApiRequest request("/contract/call", "POST", createSimpleJson(call_params_map));
    ApiResponse response = apiServer->processRequest(request);
    displayResponse(response);
}


void CliClient::displayHelp() const {
    std::cout << "\n--- CLI Commands ---" << std::endl;
    std::cout << "info                                  - Get node information." << std::endl;
    std::cout << "sendtx <recipient_id> <amount> [msg]  - Send a value transfer transaction." << std::endl;
    std::cout << "getblock <block_hash>                 - Get a block by its hash." << std::endl;
    std::cout << "balance <account_id>                  - Check an account's balance (via TokenContract)." << std::endl;
    std::cout << "mine                                  - Mine a new block (for testing)." << std::endl;
    std::cout << "deploycontract <code_name> <owner_pub_key> [initial_state_json]" << std::endl;
    std::cout << "                                      - Deploy a smart contract. Example: deploycontract TokenContract " << defaultSenderId << " {}" << std::endl;
    std::cout << "callcontract <contract_id> <method_name> [params_json] [sender_id]" << std::endl;
    std::cout << "                                      - Call a method on a deployed contract. Example: callcontract <id> transfer '{\"from\":\"A\",\"to\":\"B\",\"amount\":\"10\"}'" << std::endl;
    std::cout << "help                                  - Display this help message." << std::endl;
    std::cout << "exit                                  - Exit the client." << std::endl;
    std::cout << "--------------------" << std::endl;
}

// Parses a command string into a vector of arguments
std::vector<std::string> CliClient::parseCommand(const std::string& commandLine) {
    std::vector<std::string> args;
    std::stringstream ss(commandLine);
    std::string item;
    char in_quote = 0; // 0: no quote, 1: single quote, 2: double quote
    std::string current_arg;

    for (char c : commandLine) {
        if (c == '\'' || c == '"') {
            if (in_quote == 0) { // Start quote
                in_quote = c;
            } else if (in_quote == c) { // End quote
                in_quote = 0;
            } else { // Different quote type inside, treat as normal char
                current_arg += c;
            }
        } else if (std::isspace(c) && in_quote == 0) {
            if (!current_arg.empty()) {
                args.push_back(current_arg);
                current_arg.clear();
            }
        } else {
            current_arg += c;
        }
    }
    if (!current_arg.empty()) {
        args.push_back(current_arg);
    }
    return args;
}


// Starts the CLI client loop
void CliClient::start() {
    std::string commandLine;
    displayHelp();
    std::cout << "\nEnter command (type 'help' for options, 'exit' to quit):\n";

    while (true) {
        std::cout << "> ";
        std::getline(std::cin, commandLine);

        if (commandLine == "exit") {
            log("Exiting CLI client.");
            break;
        }
        if (commandLine.empty()) {
            continue;
        }

        std::vector<std::string> args = parseCommand(commandLine);
        if (args.empty()) {
            continue;
        }

        std::string command = args[0];
        try {
            if (command == "info") {
                handleInfoCommand();
            } else if (command == "sendtx") {
                handleSendTxCommand(args);
            } else if (command == "getblock") {
                handleGetBlockCommand(args);
            } else if (command == "balance") {
                handleBalanceCommand(args);
            } else if (command == "mine") {
                handleMineCommand();
            } else if (command == "deploycontract") {
                handleDeployContractCommand(args);
            } else if (command == "callcontract") {
                handleCallContractCommand(args);
            } else if (command == "help") {
                displayHelp();
            } else {
                std::cout << "Unknown command: " << command << ". Type 'help' for options." << std::endl;
            }
        } catch (const CliClientError& e) {
            std::cout << "CLI Error: " << e.what() << std::endl;
        } catch (const std::runtime_error& e) {
            std::cout << "Runtime Error: " << e.what() << std::endl;
        } catch (...) {
            std::cout << "An unexpected error occurred." << std::endl;
        }
        std::cout << std::endl; // Add an empty line for better readability between commands
    }
}