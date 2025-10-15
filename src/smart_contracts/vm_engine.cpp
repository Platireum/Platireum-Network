#include "vm_engine.h"
#include <iostream>
#include <stdexcept>
#include <sstream> // For parsing parameters (basic JSON parsing)


// --- VMEngine Class Implementation ---

// New constructor with WASM engine and store initialization
VMEngine::VMEngine() { // : wasmEngine(nullptr, &wasm_engine_delete), wasmStore(nullptr, &wasm_store_delete) {
    log("WASM engine and store initialization temporarily disabled.");
    // this->wasmEngine.reset(wasm_engine_new());
    // if (!this->wasmEngine) {
    //     throw VMEngineError("Failed to create WASM engine.");
    // }
    // this->wasmStore.reset(wasm_store_new(this->wasmEngine.get()));
    // if (!this->wasmStore) {
    //     throw VMEngineError("Failed to create WASM store.");
    // }
    // log("WASM engine and store initialized successfully.");
}

VMEngine::~VMEngine() {
    // Destructor for proper WASM resource cleanup (temporarily disabled)
}

// Private helper for internal logging
void VMEngine::log(const std::string& message) const {
    // std::cout << "[VMEngine] " << message << std::endl; // Uncomment for verbose logging
}

// Deploy a new smart contract with WASM bytecode validation
void VMEngine::deployContract(std::shared_ptr<SmartContract> contract, const std::vector<uint8_t>& wasmBytecode) {
    if (deployedContracts.count(contract->getId())) {
        throw VMEngineError("Contract with ID already deployed.");
    }

    // WASM bytecode validation and instantiation temporarily disabled
    // wasm_byte_vec_t wasm_bytes;
    // wasm_byte_vec_new(&wasm_bytes, wasmBytecode.size(), wasmBytecode.data());

    // if (!wasm_module_validate(wasmStore.get(), &wasm_bytes)) {
    //     wasm_byte_vec_delete(&wasm_bytes);
    //     throw VMEngineError("Invalid WASM bytecode provided for contract.");
    // }
    // wasm_byte_vec_delete(&wasm_bytes);

    deployedContracts[contract->getId()] = contract;
    log("Validated and deployed contract (WASM validation skipped): " + contract->getId());
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

    // Placeholder for actual function execution logic
    // In a real system, this would involve:
    // - Compiling and instantiating the WASM module if not already done
    // - Setting up host functions (callbacks to the blockchain)
    // - Calling the exported function from the contract
    // - Handling parameters and return values

    // For now, we'll use a simplified logic based on contract code string
    const std::vector<uint8_t>& contractBytecode = contract->getBytecode();

    // For now, we'll use a simplified logic based on a hardcoded contract ID for demonstration
    // In a real system, this would involve actual WASM execution based on the bytecode.
    // We'll check the contract ID to simulate different contract behaviors.
    std::string contractIdentifier = contract->getId(); // Using ID as a simple identifier for logic

    if (contractIdentifier == "TokenContract") {
        // Example: A simple fungible token contract
        // Methods: 'mint', 'transfer', 'balanceOf'
        log("Executing TokenContract method: " + methodName + " by " + senderId);
        auto params = parseSimpleJson(paramsJson);

        if (methodName == "mint") {
            if (senderId != contract->getOwnerPublicKey()) {
                return "Error: Only contract owner can mint tokens.";
            }
            if (params.count("recipient") && params.count("amount")) {
                std::string recipient = params["recipient"];
                double amount = std::stod(params["amount"]);

                // Simplified balance management within the contract state
                double currentBalance = 0.0;
                try { currentBalance = std::stod(contract->getState("balance_" + recipient)); }
                catch (...) {}

                double newBalance = currentBalance + amount;
                contract->setState("balance_" + recipient, std::to_string(newBalance));
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
                try { fromBalance = std::stod(contract->getState("balance_" + from)); }
                catch (...) {}

                if (fromBalance < amount) {
                    return "Error: Insufficient balance for transfer.";
                }

                double toBalance = 0.0;
                try { toBalance = std::stod(contract->getState("balance_" + to)); }
                catch (...) {}

                contract->setState("balance_" + from, std::to_string(fromBalance - amount));
                contract->setState("balance_" + to, std::to_string(toBalance + amount));
                log("Internal transfer of " + std::to_string(amount) + " from " + from + " to " + to +
                    ". New balances: " + from + "=" + std::to_string(fromBalance - amount) +
                    ", " + to + "=" + std::to_string(toBalance + amount));
                
                return "Success: " + std::to_string(amount) + " tokens transferred from " + from + " to " + to;
            }
            return "Error: Missing from, to, or amount for transfer.";
        }
        else if (methodName == "balanceOf") {
            if (params.count("account")) {
                std::string account = params["account"];
                double balance = 0.0;
                try { balance = std::stod(contract->getState("balance_" + account)); }
                catch (...) {}
                return "Success: Balance of " + account + " is " + std::to_string(balance);
            }
            return "Error: Missing account for balanceOf.";
        }
        return "Error: Unknown method for TokenContract: " + methodName;
    }
    else {
        return "Error: Unknown contract logic for " + contract->getId().substr(0, 8) + "... or method: " + methodName;
    }
}

std::shared_ptr<SmartContract> VMEngine::getContract(const std::string& contractId) const {
    auto it = deployedContracts.find(contractId);
    if (it != deployedContracts.end()) {
        return it->second;
    }
    return nullptr;
}

bool VMEngine::hasContract(const std::string& contractId) const {
    return deployedContracts.count(contractId) > 0;
}

// Temporarily disabled WASM instance retrieval
// wasm_instance_t* VMEngine::getWASMInstance(const std::string& contractId) const {
//     return nullptr; // WASM functionality disabled
// }

void VMEngine::loadDeployedContracts(
    const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& contractMap,
    std::function<std::vector<uint8_t>(const std::string&)> wasmBytecodeProvider) {
    log("Loading deployed contracts (WASM instantiation skipped)...");
    for (const auto& pair : contractMap) {
        // In a full WASM implementation, you would re-instantiate the WASM module here.
        // For now, just add the contract to the map.
        deployedContracts[pair.first] = pair.second;
        log("Loaded contract: " + pair.first);
    }
}

