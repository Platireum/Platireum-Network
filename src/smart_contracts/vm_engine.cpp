#include "vm_engine.h"
#include <iostream>
#include <stdexcept>
#include <sstream> // For parsing parameters (basic JSON parsing)

// --- Helper for simple JSON parsing (for contract parameters) ---
// This is a very rudimentary JSON parser. In a real-world scenario,
// use a robust JSON library like nlohmann/json.
std::unordered_map<std::string, std::string> parseSimpleJson(const std::string& jsonString) {
    std::unordered_map<std::string, std::string> params;
    if (jsonString.empty() || jsonString == "{}") {
        return params;
    }

    std::string cleanJson = jsonString;
    // Remove outer braces if present
    if (cleanJson.front() == '{' && cleanJson.back() == '}') {
        cleanJson = cleanJson.substr(1, cleanJson.length() - 2);
    }

    std::stringstream ss(cleanJson);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        size_t colonPos = segment.find(':');
        if (colonPos == std::string::npos) {
            continue; // Invalid segment
        }

        std::string key = segment.substr(0, colonPos);
        std::string value = segment.substr(colonPos + 1);

        // Trim whitespace and remove quotes
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        if (key.length() >= 2 && key.front() == '"' && key.back() == '"') {
            key = key.substr(1, key.length() - 2);
        }

        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.length() - 2);
        }
        
        params[key] = value;
    }
    return params;
}

// --- تنفيذ دوال فئة VMEngine ---

VMEngine::VMEngine() {
    // Constructor for VMEngine
}

// Private helper for internal logging
void VMEngine::log(const std::string& message) const {
    // std::cout << "[VMEngine] " << message << std::endl; // Uncomment for verbose logging
}

// Binds predefined C++ logic to a contract based on its code
void VMEngine::bindContractLogic(std::shared_ptr<SmartContract> contract) {
    // This is where we simulate the "bytecode execution" or "script interpretation"
    // by mapping contractCode to specific C++ lambda functions.
    // In a real VM, contractCode would be actual bytecode, and the VM would interpret it.

    std::string contractCode = contract->getCode();

    if (contractCode == "TokenContract") {
        // Example: A simple fungible token contract
        // Methods: 'mint', 'transfer', 'balanceOf'
        contract->setExecutionLogic(
            [this](const std::string& senderId, const std::string& methodName, const std::string& paramsJson, SmartContract& currentContract) -> std::string {
                log("Executing TokenContract method: " + methodName + " by " + senderId);
                auto params = parseSimpleJson(paramsJson);

                if (methodName == "mint") {
                    if (senderId != currentContract.getOwnerPublicKey()) {
                        return "Error: Only contract owner can mint tokens.";
                    }
                    if (params.count("recipient") && params.count("amount")) {
                        std::string recipient = params["recipient"];
                        double amount = std::stod(params["amount"]);
                        
                        double currentBalance = 0.0;
                        if (this->onGetBalanceCallback) { // Check if callback is set
                            currentBalance = this->onGetBalanceCallback(recipient);
                        } else {
                            // If no external balance callback, manage balance internally for simplicity
                            try { currentBalance = std::stod(currentContract.getState("balance_" + recipient)); } catch (...) {}
                        }
                        
                        double newBalance = currentBalance + amount;
                        currentContract.setState("balance_" + recipient, std::to_string(newBalance));
                        log("Minted " + std::to_string(amount) + " to " + recipient + ". New balance: " + std::to_string(newBalance));
                        return "Success: " + std::to_string(amount) + " tokens minted to " + recipient;
                    }
                    return "Error: Missing recipient or amount for mint.";
                }
                else if (methodName == "transfer") {
                    if (params.count("from") && params.count("to") && params.count("amount")) {
                        std::string from = params["from"];
                        std::string to = params["to"];
                        double amount = std::stod(params["amount"]);

                        if (senderId != from) { // Ensure the caller is the 'from' account (simple auth)
                             return "Error: Sender must be the 'from' account for transfer.";
                        }

                        double fromBalance = 0.0;
                        if (this->onGetBalanceCallback) {
                             fromBalance = this->onGetBalanceCallback(from);
                        } else {
                            try { fromBalance = std::stod(currentContract.getState("balance_" + from)); } catch (...) {}
                        }

                        if (fromBalance < amount) {
                            return "Error: Insufficient balance for transfer.";
                        }

                        if (this->onTransferFundsCallback) {
                            // Delegate actual fund transfer to the blockchain layer (Node)
                            this->onTransferFundsCallback(from, to, amount);
                            log("Requested external transfer of " + std::to_string(amount) + " from " + from + " to " + to);
                            // The actual balance update on UTXO set will happen in Node
                        } else {
                            // Fallback: manage internal state if no external callback
                            double toBalance = 0.0;
                            try { toBalance = std::stod(currentContract.getState("balance_" + to)); } catch (...) {}
                            
                            currentContract.setState("balance_" + from, std::to_string(fromBalance - amount));
                            currentContract.setState("balance_" + to, std::to_string(toBalance + amount));
                            log("Internal transfer of " + std::to_string(amount) + " from " + from + " to " + to +
                                ". New balances: " + from + "=" + std::to_string(fromBalance - amount) +
                                ", " + to + "=" + std::to_string(toBalance + amount));
                        }
                        return "Success: " + std::to_string(amount) + " tokens transferred from " + from + " to " + to;
                    }
                    return "Error: Missing from, to, or amount for transfer.";
                }
                else if (methodName == "balanceOf") {
                    if (params.count("account")) {
                        std::string account = params["account"];
                        double balance = 0.0;
                        if (this->onGetBalanceCallback) {
                            balance = this->onGetBalanceCallback(account); // Get actual balance from blockchain layer
                        } else {
                            try { balance = std::stod(currentContract.getState("balance_" + account)); } catch (...) {}
                        }
                        return "Success: Balance of " + account + " is " + std::to_string(balance);
                    }
                    return "Error: Missing account for balanceOf.";
                }
                return "Error: Unknown method for TokenContract: " + methodName;
            }
        );
    } else {
        // Default behavior for unknown contracts
        contract->setExecutionLogic(
            [](const std::string& senderId, const std::string& methodName, const std::string& paramsJson, SmartContract& currentContract) -> std::string {
                return "Error: Unknown contract logic for " + currentContract.getId().substr(0,8) + "... or method: " + methodName;
            }
        );
    }
}

// Deploy a new smart contract
void VMEngine::deployContract(std::shared_ptr<SmartContract> contract) {
    if (deployedContracts.count(contract->getId())) {
        throw VMEngineError("Contract with ID " + contract->getId() + " already deployed.");
    }
    // Bind the predefined logic to the contract based on its code
    bindContractLogic(contract);
    deployedContracts[contract->getId()] = contract;
    log("Deployed contract: " + contract->getId().substr(0, 8) + "...");
}

// Execute a function within a deployed smart contract
std::string VMEngine::executeContract(const std::string& contractId,
                                     const std::string& senderId,
                                     const std::string& methodName,
                                     const std::string& paramsJson) {
    auto it = deployedContracts.find(contractId);
    if (it == deployedContracts.end()) {
        throw VMEngineError("Contract with ID " + contractId + " not found.");
    }
    // Call the contract's execute method, which uses the bound executionLogic
    return it->second->execute(senderId, methodName, paramsJson);
}

// Retrieve a deployed smart contract
std::shared_ptr<SmartContract> VMEngine::getContract(const std::string& contractId) const {
    auto it = deployedContracts.find(contractId);
    if (it != deployedContracts.end()) {
        return it->second;
    }
    return nullptr;
}

// Check if a contract is deployed
bool VMEngine::hasContract(const std::string& contractId) const {
    return deployedContracts.count(contractId) > 0;
}

// Load deployed contracts from persistent storage (e.g., from StorageManager)
void VMEngine::loadDeployedContracts(const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& contractMap) {
    deployedContracts.clear(); // Clear existing contracts
    for (const auto& pair : contractMap) {
        // Re-bind logic for loaded contracts as they are newly created objects
        bindContractLogic(pair.second);
        deployedContracts[pair.first] = pair.second;
        log("Loaded and bound contract: " + pair.first.substr(0, 8) + "...");
    }
    log("Loaded " + std::to_string(deployedContracts.size()) + " contracts into VM.");
}