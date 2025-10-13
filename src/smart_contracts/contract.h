#ifndef SMART_CONTRACT_H
#define SMART_CONTRACT_H

#include <string>
#include <vector>
#include <unordered_map>
#include <functional> // For std::function - might be removed if no longer needed
#include <memory>     // For std::shared_ptr

// Forward declarations to break circular dependencies if needed later
// class Node; // If contract needs to interact directly with node's state

/**
 * @brief Represents a simple Smart Contract in our simulated environment.
 * In a real blockchain, contracts have their own address, state, and bytecode.
 * Now we use actual WASM bytecode instead of symbolic names.
 */
class SmartContract {
private:
    std::string contractId; // Unique identifier for this contract (e.g., hash of deploy transaction)
    std::vector<uint8_t> contractBytecode; // The actual WASM bytecode of the contract (CHANGED)
    std::string ownerPublicKey; // Public key of the deployer

    // A simplified state for the contract. In reality, this would be a Merkle Patricia Trie
    // or similar data structure persisted on chain.
    std::unordered_map<std::string, std::string> contractState;

    // REMOVED: executionLogic callback - execution responsibility moved to VMEngine

public:
    /**
     * @brief Constructor for SmartContract.
     * @param id Unique ID of the contract.
     * @param bytecode The contract's actual WASM bytecode.
     * @param owner The public key of the contract owner/deployer.
     */
    SmartContract(const std::string& id,
        const std::vector<uint8_t>& bytecode,
        const std::string& owner);

    // Getters
    const std::string& getId() const { return contractId; }
    const std::vector<uint8_t>& getBytecode() const { return contractBytecode; } // CHANGED
    const std::string& getOwnerPublicKey() const { return ownerPublicKey; }

    // State management for the contract (simplified)
    void setState(const std::string& key, const std::string& value);
    std::string getState(const std::string& key) const;

    // REMOVED: setExecutionLogic method - execution logic is now embedded in bytecode

    // REMOVED: execute method - execution responsibility moved to VMEngine

    // Serialization/Deserialization (for persistence)
    // Note: These will need to handle binary bytecode (convert to/from Base64 for JSON storage)
    std::string serialize() const;
    static std::shared_ptr<SmartContract> deserialize(const std::string& data);
};

#endif // SMART_CONTRACT_H
