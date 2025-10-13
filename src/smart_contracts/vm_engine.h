#ifndef VM_ENGINE_H
#define VM_ENGINE_H

#include <string>
#include <memory>         // For std::shared_ptr
#include <unordered_map>  // To manage deployed contracts
#include <stdexcept>      // For custom exceptions
#include <functional>     // For std::function (for any remaining utility callbacks)

// Include necessary headers from our project structure
#include "contract.h" // For SmartContract class

// Includes for WASM runtime, e.g., Wasmer
#include "wasmer.h"

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
 * @brief A Virtual Machine (VM) Engine for executing WASM-based smart contracts.
 *
 * This VM uses a WASM runtime (e.g., Wasmer) to execute contract bytecode in a secure,
 * sandboxed environment. It manages deployed contracts and their state, and provides
 * an execution environment with host functions for blockchain interactions.
 *
 * The engine handles WASM module compilation, instantiation, and execution while
 * providing controlled access to blockchain resources through host functions.
 */
class VMEngine {
private:
    // Store deployed contracts by their ID
    std::unordered_map<std::string, std::shared_ptr<SmartContract>> deployedContracts;

    // WASM Runtime Components (new)
    // Using unique_ptr with custom deleters to ensure proper resource cleanup
    std::unique_ptr<wasm_engine_t, decltype(&wasm_engine_delete)> wasmEngine;
    std::unique_ptr<wasm_store_t, decltype(&wasm_store_delete)> wasmStore;

    // Store WASM instances for deployed contracts
    // Contract ID -> WASM instance
    std::unordered_map<std::string, std::unique_ptr<wasm_instance_t, decltype(&wasm_instance_delete)>> wasmInstances;

    // Private helper for internal logging
    void log(const std::string& message) const;

    /**
     * @brief Compiles and instantiates a WASM module from bytecode.
     * This replaces the old bindContractLogic method.
     * @param contractId The ID of the contract being deployed.
     * @param wasmBytecode The WASM bytecode to compile and instantiate.
     * @throws VMEngineError if compilation or instantiation fails.
     */
    void instantiateWASMModule(const std::string& contractId, const std::vector<uint8_t>& wasmBytecode);

    /**
     * @brief Defines host functions that contracts can call to interact with the blockchain.
     * These functions replace the old callback system with a more secure, sandboxed approach.
     * @param imports The imports object to which host functions will be added.
     */
    void setupHostFunctions(wasm_importtype_vec_t* imports);

public:
    VMEngine(); // Constructor
    ~VMEngine(); // Destructor for proper WASM resource cleanup

    /**
     * @brief Deploys a new smart contract to the VM with WASM bytecode.
     * This compiles and instantiates the WASM module for the contract.
     * @param contract A shared_ptr to the SmartContract object to deploy.
     * @param wasmBytecode The WASM bytecode of the contract.
     * @throws VMEngineError if a contract with the same ID already exists or WASM instantiation fails.
     */
    void deployContract(std::shared_ptr<SmartContract> contract, const std::vector<uint8_t>& wasmBytecode);

    /**
     * @brief Executes a function within a deployed smart contract using WASM.
     * This function is the primary entry point for contract interactions.
     * @param contractId The ID of the contract to execute.
     * @param senderId The public key of the account calling the contract (e.g., from a transaction).
     * @param methodName The name of the method/function to call within the contract.
     * @param paramsJson A JSON string containing parameters for the method.
     * @return A string representing the result of the execution.
     * @throws VMEngineError if the contract is not found or WASM execution fails.
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

    /**
     * @brief Gets the WASM instance for a specific contract.
     * @param contractId The ID of the contract.
     * @return Pointer to the WASM instance, or nullptr if not found.
     */
    wasm_instance_t* getWASMInstance(const std::string& contractId) const;

    // --- Persistence (for saving/loading deployed contracts) ---
    // These functions would interact with the StorageManager.
    // They are typically managed by the Node/Blockchain, not VM directly.
    // However, the VM needs to provide a way to load contracts.

    /**
     * @brief Loads deployed contracts from persistent storage (e.g., via StorageManager).
     * This would typically be called during node startup and would need to reinstantiate WASM modules.
     * @param contractMap The map of contracts to load into the VM.
     * @param wasmBytecodeProvider A function that provides WASM bytecode for a given contract ID.
     */
    void loadDeployedContracts(
        const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& contractMap,
        std::function<std::vector<uint8_t>(const std::string&)> wasmBytecodeProvider);

    /**
     * @brief Returns a map of all currently deployed contracts.
     * Useful for persisting the VM state (e.g., to StorageManager).
     */
    const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& getAllDeployedContracts() const {
        return deployedContracts;
    }

    // Note: The old callback setters (setOnTransferFundsCallback, setOnGetBalanceCallback) 
    // have been removed. Blockchain interactions are now handled through host functions
    // that are set up during WASM module instantiation, providing a more secure and
    // sandboxed environment for contract execution.
};

#endif // VM_ENGINE_H
