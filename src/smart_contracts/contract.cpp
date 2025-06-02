#include "contract.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

// Constructor
SmartContract::SmartContract(const std::string& id, const std::string& code, const std::string& owner)
    : contractId(id), contractCode(code), ownerPublicKey(owner) {
    // Initial state can be empty or set by deployer
}

// Set a key-value pair in the contract's state
void SmartContract::setState(const std::string& key, const std::string& value) {
    contractState[key] = value;
    // In a real system, state changes would be hashed and committed to the blockchain.
    // This simplified model just updates the in-memory map.
    // std::cout << "[Contract " << contractId.substr(0, 8) << "...] State updated: " << key << " = " << value << std::endl;
}

// Get a value from the contract's state
std::string SmartContract::getState(const std::string& key) const {
    auto it = contractState.find(key);
    if (it != contractState.end()) {
        return it->second;
    }
    // Return empty string if key not found (or throw an exception based on design choice)
    return "";
}

// Execute the contract's logic
std::string SmartContract::execute(const std::string& senderId, const std::string& methodName, const std::string& paramsJson) {
    if (executionLogic) {
        // Pass a reference to 'this' (the current contract instance) to the execution logic
        // This allows the logic to modify the contract's state using setState().
        return executionLogic(senderId, methodName, paramsJson, *this);
    } else {
        throw std::runtime_error("Contract execution logic not set for contract: " + contractId);
    }
}

// --- Serialization/Deserialization ---
// A simple JSON-like serialization format for demonstration:
// { "id": "...", "code": "...", "owner": "...", "state": { "key1": "value1", "key2": "value2" } }

std::string SmartContract::serialize() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"id\":\"" << contractId << "\",";
    ss << "\"code\":\"" << contractCode << "\",";
    ss << "\"owner\":\"" << ownerPublicKey << "\",";
    ss << "\"state\":{";
    bool first_state_entry = true;
    for (const auto& pair : contractState) {
        if (!first_state_entry) {
            ss << ",";
        }
        // Escape quotes within key/value if necessary for robustness
        ss << "\"" << pair.first << "\":\"" << pair.second << "\"";
        first_state_entry = false;
    }
    ss << "}"; // Close state object
    ss << "}"; // Close main object
    return ss.str();
}

// This deserialization is basic and assumes a perfect input format.
// A robust solution would use a proper JSON parsing library.
std::shared_ptr<SmartContract> SmartContract::deserialize(const std::string& data) {
    std::string id, code, owner;
    std::unordered_map<std::string, std::string> state;

    // Basic parsing logic (very fragile, use a JSON library in production)
    size_t id_pos = data.find("\"id\":\"");
    size_t code_pos = data.find("\"code\":\"");
    size_t owner_pos = data.find("\"owner\":\"");
    size_t state_pos = data.find("\"state\":{");

    if (id_pos == std::string::npos || code_pos == std::string::npos ||
        owner_pos == std::string::npos || state_pos == std::string::npos) {
        throw std::runtime_error("Failed to parse SmartContract: Missing essential fields.");
    }

    // Extracting id
    id_pos += 6; // Move past "id":"
    size_t id_end = data.find("\"", id_pos);
    if (id_end == std::string::npos) throw std::runtime_error("Invalid contract ID format.");
    id = data.substr(id_pos, id_end - id_pos);

    // Extracting code
    code_pos += 8; // Move past "code":"
    size_t code_end = data.find("\"", code_pos);
    if (code_end == std::string::npos) throw std::runtime_error("Invalid contract code format.");
    code = data.substr(code_pos, code_end - code_pos);

    // Extracting owner
    owner_pos += 9; // Move past "owner":"
    size_t owner_end = data.find("\"", owner_pos);
    if (owner_end == std::string::npos) throw std::runtime_error("Invalid contract owner format.");
    owner = data.substr(owner_pos, owner_end - owner_pos);

    // Extracting state
    state_pos += 9; // Move past "state":{"
    size_t state_end = data.find("}", state_pos); // Find closing brace of state object
    if (state_end == std::string::npos) throw std::runtime_error("Invalid contract state format.");
    std::string state_str = data.substr(state_pos, state_end - state_pos);

    // Parse state key-value pairs
    std::stringstream ss(state_str);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        size_t colon_pos = segment.find(':');
        if (colon_pos == std::string::npos) continue;

        std::string key = segment.substr(0, colon_pos);
        std::string value = segment.substr(colon_pos + 1);

        // Remove quotes from key and value
        if (key.length() >= 2 && key.front() == '"' && key.back() == '"') {
            key = key.substr(1, key.length() - 2);
        }
        if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.length() - 2);
        }
        if (!key.empty()) {
            state[key] = value;
        }
    }

    std::shared_ptr<SmartContract> contract = std::make_shared<SmartContract>(id, code, owner);
    contract->contractState = state; // Directly assign the parsed state
    return contract;
}