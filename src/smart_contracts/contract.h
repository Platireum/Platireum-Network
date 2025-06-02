#ifndef SMART_CONTRACT_H
#define SMART_CONTRACT_H

#include <string>
#include <vector>
#include <unordered_map>
#include <functional> // For std::function
#include <memory>     // For std::shared_ptr

// Forward declarations to break circular dependencies if needed later
// class Node; // If contract needs to interact directly with node's state

/**
 * @brief Represents a simple Smart Contract in our simulated environment.
 * In a real blockchain, contracts have their own address, state, and bytecode.
 * Here, we simplify by associating a unique ID and possibly some basic state.
 */
class SmartContract {
private:
    std::string contractId; // Unique identifier for this contract (e.g., hash of deploy transaction)
    std::string contractCode; // The "code" of the contract (simplified: just a string for now)
    std::string ownerPublicKey; // Public key of the deployer
    
    // A simplified state for the contract. In reality, this would be a Merkle Patricia Trie
    // or similar data structure persisted on chain.
    std::unordered_map<std::string, std::string> contractState;

    // A callback for the VM to execute the contract's logic.
    // This is a placeholder for a more complex VM execution model.
    std::function<std::string(const std::string&, const std::string&, const std::string&, SmartContract&)> executionLogic;

public:
    /**
     * @brief Constructor for SmartContract.
     * @param id Unique ID of the contract.
     * @param code The contract's code (e.g., a simple script or identifier).
     * @param owner The public key of the contract owner/deployer.
     */
    SmartContract(const std::string& id, const std::string& code, const std::string& owner);

    // Getters
    const std::string& getId() const { return contractId; }
    const std::string& getCode() const { return contractCode; }
    const std::string& getOwnerPublicKey() const { return ownerPublicKey; }
    
    // State management for the contract (simplified)
    void setState(const std::string& key, const std::string& value);
    std::string getState(const std::string& key) const;
    
    /**
     * @brief Sets the external execution logic for the contract.
     * This allows the VM engine to define how this contract behaves.
     * @param logic The function that represents the contract's executable logic.
     * Parameters: (sender_id, method_name, params_json, SmartContract& current_contract)
     * Returns: execution result/error string.
     */
    void setExecutionLogic(std::function<std::string(const std::string&, const std::string&, const std::string&, SmartContract&)> logic) {
        executionLogic = std::move(logic);
    }

    /**
     * @brief Executes the contract's logic. This method would be called by the VM engine.
     * @param senderId The ID of the account calling the contract.
     * @param methodName The method/function within the contract to call.
     * @param paramsJson A JSON string of parameters for the method.
     * @return A string representing the result or an error message.
     */
    std::string execute(const std::string& senderId, const std::string& methodName, const std::string& paramsJson);

    // Serialization/Deserialization (for persistence)
    std::string serialize() const;
    static std::shared_ptr<SmartContract> deserialize(const std::string& data);
};

#endif // SMART_CONTRACT_H