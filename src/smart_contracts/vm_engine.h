#ifndef VM_ENGINE_H
#define VM_ENGINE_H

#include <string>
#include <memory>         // For std::shared_ptr
#include <unordered_map>  // To manage deployed contracts
#include <stdexcept>      // For custom exceptions
#include <functional>     // For std::function (callbacks)

// Include necessary headers from our project structure
#include "contract.h" // For SmartContract class
// We'll need access to UTXO set for contract balance updates (from FinalityChain)
// For now, we'll use a callback or pass necessary data directly.
// If VMEngine needs to interact deeply with FinalityChain or DAG, consider forward declarations
// or passing an interface/callbacks to avoid tight coupling.

// Forward declarations if VMEngine needs to hold pointers to Node components
// This avoids circular dependencies and keeps the VM layer cleaner.
class Transaction; // To pass contract-related transactions
class FinalityChain; // To access blockchain state like UTXO set
class TransactionDAG; // To access DAG state

// --- 0. Error Handling ---
/**
 * @brief Custom exception class for VMEngine-specific errors.
 */
class VMEngineError : public std::runtime_error {
public:
    explicit VMEngineError(const std::string& msg) : std::runtime_error(msg) {}
};

// --- 1. VMEngine Class ---
/**
 * @brief A simplified Virtual Machine (VM) Engine for executing smart contracts.
 *
 * This VM is highly abstracted. Instead of bytecode execution, it relies on
 * predefined C++ functions (or simple script-like logic) associated with contract IDs.
 * It manages deployed contracts and their state, and provides an execution environment.
 *
 * In a real blockchain, this would be a full-fledged interpreter/compiler for a
 * low-level bytecode, managing gas, stack, memory, and persistent storage.
 */
class VMEngine {
private:
    // Store deployed contracts by their ID
    std::unordered_map<std::string, std::shared_ptr<SmartContract>> deployedContracts;

    // Callbacks to interact with the broader blockchain state (e.g., Node, FinalityChain)
    // This allows the VM to read/write from the blockchain's UTXO set or state.
    // Example: A contract might need to debit/credit funds.
    std::function<void(const std::string&, const std::string&, double)> onTransferFundsCallback;
    std::function<double(const std::string&)> onGetBalanceCallback;
    // ... add more callbacks for blockchain interactions (e.g., getBlockInfo, getTxStatus)

    // Private helper for internal logging
    void log(const std::string& message) const;

    /**
     * @brief Internal helper to bind predefined C++ logic to a contract.
     * This simulates the "execution environment" for contracts.
     * In a real VM, this is where bytecode interpretation happens.
     * @param contract The SmartContract object to bind logic to.
     */
    void bindContractLogic(std::shared_ptr<SmartContract> contract);

public:
    VMEngine(); // Constructor

    /**
     * @brief Deploys a new smart contract to the VM.
     * This simulates adding a new contract to the blockchain state.
     * @param contract A shared_ptr to the SmartContract object to deploy.
     * @throws VMEngineError if a contract with the same ID already exists.
     */
    void deployContract(std::shared_ptr<SmartContract> contract);

    /**
     * @brief Executes a function within a deployed smart contract.
     * This function is the primary entry point for contract interactions.
     * @param contractId The ID of the contract to execute.
     * @param senderId The public key of the account calling the contract (e.g., from a transaction).
     * @param methodName The name of the method/function to call within the contract.
     * @param paramsJson A JSON string containing parameters for the method.
     * @return A string representing the result of the execution.
     * @throws VMEngineError if the contract is not found or execution fails.
     */
    std::string executeContract(const std::string& contractId,
                                const std::string& senderId,
                                const std::string& methodName,
                                const std::string& paramsJson);

    /**
     * @brief Retrieves a deployed smart contract by its ID.
     * @param contractId The ID of the contract to retrieve.
     * @return A shared_ptr to the SmartContract, or nullptr if not found.
     */
    std::shared_ptr<SmartContract> getContract(const std::string& contractId) const;

    /**
     * @brief Checks if a contract with the given ID is deployed.
     * @param contractId The ID of the contract to check.
     * @return True if the contract is deployed, false otherwise.
     */
    bool hasContract(const std::string& contractId) const;

    // --- Callbacks for external interactions ---
    /**
     * @brief Sets a callback function for when a contract wants to transfer funds.
     * This connects the VM's internal "transfer" operation to the blockchain's UTXO management.
     * @param callback A function taking (sender_id, recipient_id, amount).
     */
    void setOnTransferFundsCallback(std::function<void(const std::string&, const std::string&, double)> callback) {
        onTransferFundsCallback = std::move(callback);
    }

    /**
     * @brief Sets a callback function for when a contract wants to query an account's balance.
     * @param callback A function taking (account_id) and returning its balance.
     */
    void setOnGetBalanceCallback(std::function<double(const std::string&)> callback) {
        onGetBalanceCallback = std::move(callback);
    }

    // --- Persistence (for saving/loading deployed contracts) ---
    // These functions would interact with the StorageManager.
    // They are typically managed by the Node/Blockchain, not VM directly.
    // However, the VM needs to provide a way to load contracts.

    /**
     * @brief Loads deployed contracts from persistent storage (e.g., via StorageManager).
     * This would typically be called during node startup.
     * @param contractMap The map of contracts to load into the VM.
     */
    void loadDeployedContracts(const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& contractMap);

    /**
     * @brief Returns a map of all currently deployed contracts.
     * Useful for persisting the VM state (e.g., to StorageManager).
     */
    const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& getAllDeployedContracts() const {
        return deployedContracts;
    }
};

#endif // VM_ENGINE_H