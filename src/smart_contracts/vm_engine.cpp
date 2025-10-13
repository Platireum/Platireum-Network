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

// --- VMEngine Class Implementation ---

// New constructor with WASM engine and store initialization
VMEngine::VMEngine() : wasmEngine(nullptr, &wasm_engine_delete), wasmStore(nullptr, &wasm_store_delete) {
    log("Initializing WASM engine...");
    this->wasmEngine.reset(wasm_engine_new());
    if (!this->wasmEngine) {
        throw VMEngineError("Failed to create WASM engine.");
    }
    this->wasmStore.reset(wasm_store_new(this->wasmEngine.get()));
    if (!this->wasmStore) {
        throw VMEngineError("Failed to create WASM store.");
    }
    log("WASM engine and store initialized successfully.");
}

// Private helper for internal logging
void VMEngine::log(const std::string& message) const {
    // std::cout << "[VMEngine] " << message << std::endl; // Uncomment for verbose logging
}

// Binds predefined C++ logic to a contract based on its code
// NOTE: This function is kept for backward compatibility but will be deprecated
// in favor of actual WASM execution
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
                        }
                        else {
                            // If no external balance callback, manage balance internally for simplicity
                            try { currentBalance = std::stod(currentContract.getState("balance_" + recipient)); }
                            catch (...) {}
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
                        }
                        else {
                            try { fromBalance = std::stod(currentContract.getState("balance_" + from)); }
                            catch (...) {}
                        }

                        if (fromBalance < amount) {
                            return "Error: Insufficient balance for transfer.";
                        }

                        if (this->onTransferFundsCallback) {
                            // Delegate actual fund transfer to the blockchain layer (Node)
                            this->onTransferFundsCallback(from, to, amount);
                            log("Requested external transfer of " + std::to_string(amount) + " from " + from + " to " + to);
                            // The actual balance update on UTXO set will happen in Node
                        }
                        else {
                            // Fallback: manage internal state if no external callback
                            double toBalance = 0.0;
                            try { toBalance = std::stod(currentContract.getState("balance_" + to)); }
                            catch (...) {}

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
                        }
                        else {
                            try { balance = std::stod(currentContract.getState("balance_" + account)); }
                            catch (...) {}
                        }
                        return "Success: Balance of " + account + " is " + std::to_string(balance);
                    }
                    return "Error: Missing account for balanceOf.";
                }
                return "Error: Unknown method for TokenContract: " + methodName;
            }
        );
    }
    else {
        // Default behavior for unknown contracts
        contract->setExecutionLogic(
            [](const std::string& senderId, const std::string& methodName, const std::string& paramsJson, SmartContract& currentContract) -> std::string {
                return "Error: Unknown contract logic for " + currentContract.getId().substr(0, 8) + "... or method: " + methodName;
            }
        );
    }
}

// Deploy a new smart contract with WASM bytecode validation
void VMEngine::deployContract(std::shared_ptr<SmartContract> contract) {
    if (deployedContracts.count(contract->getId())) {
        throw VMEngineError("Contract with ID already deployed.");
    }

    // Convert bytecode from vector to WASM-compatible format
    wasm_byte_vec_t wasm_bytes;
    wasm_byte_vec_new(&wasm_bytes, contract->getBytecode().size(), contract->getBytecode().data());

    // Validate that the bytecode is a valid WASM module
    if (!wasm_module_validate(wasmStore.get(), &wasm_bytes)) {
        wasm_byte_vec_delete(&wasm_bytes);
        throw VMEngineError("Invalid WASM bytecode provided for contract.");
    }

    wasm_byte_vec_delete(&wasm_bytes);
    deployedContracts[contract->getId()] = contract;
    log("Validated and deployed WASM contract: " + contract->getId());
}

// Execute a function within a deployed smart contract using actual WASM execution
std::string VMEngine::executeContract(const std::string& contractId,
    const std::string& senderId,
    const std::string& methodName,
    const std::string& paramsJson) {
    auto it = deployedContracts.find(contractId);
    if (it == deployedContracts.end()) {
        throw VMEngineError("Contract with ID " + contractId + " not found.");
    }

    auto contract = it->second;

    // 1. Get contract and bytecode
    wasm_byte_vec_t wasm_bytes;
    wasm_byte_vec_new(&wasm_bytes, contract->getBytecode().size(), contract->getBytecode().data());

    // 2. Compile bytecode into executable module
    wasm_module_t* module = wasm_module_new(wasmStore.get(), &wasm_bytes);
    wasm_byte_vec_delete(&wasm_bytes);
    if (!module) {
        throw VMEngineError("Failed to compile WASM module for contract: " + contractId);
    }

    // 3. Define "Host Functions" that the contract can call
    // Example: A C++ function that allows the contract to request state modification on the blockchain
    // auto host_set_state_func = wasm_func_new_with_env(...);

    // Create an import object for host functions (empty for now - will be implemented in next phase)
    wasm_extern_vec_t import_object = WASM_EMPTY_VEC;

    // 4. Create isolated instance and bind host functions to it
    wasm_instance_t* instance = wasm_instance_new(wasmStore.get(), module, &import_object, nullptr);
    if (!instance) {
        wasm_module_delete(module);
        throw VMEngineError("Failed to create WASM instance for contract: " + contractId);
    }

    // 5. Call the exported function from the contract (e.g., 'call')
    // This would involve:
    // - Getting the exported function by name
    // - Preparing parameters (converting from JSON to WASM values)
    // - Calling the function
    // - Processing the result (converting from WASM values to string)

    // Placeholder for actual function execution logic
    std::string result = "Execution result for method '" + methodName + "' from contract '" + contractId + "' by '" + senderId + "' with params: " + paramsJson;

    // 6. Free resources
    wasm_instance_delete(instance);
    wasm_module_delete(module);

    log("Executed WASM contract: " + contractId + " method: " + methodName);
    return result;
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
        // For loaded contracts, we need to validate their WASM bytecode again
        // and prepare them for execution
        auto contract = pair.second;

        // Validate WASM bytecode for loaded contracts
        wasm_byte_vec_t wasm_bytes;
        wasm_byte_vec_new(&wasm_bytes, contract->getBytecode().size(), contract->getBytecode().data());

        if (!wasm_module_validate(wasmStore.get(), &wasm_bytes)) {
            wasm_byte_vec_delete(&wasm_bytes);
            log("Warning: Invalid WASM bytecode for loaded contract: " + pair.first);
            continue; // Skip invalid contracts
        }

        wasm_byte_vec_delete(&wasm_bytes);
        deployedContracts[pair.first] = contract;
        log("Loaded and validated WASM contract: " + pair.first);
    }
    log("Loaded " + std::to_string(deployedContracts.size()) + " contracts into VM.");
}
