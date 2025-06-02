#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include <string>
#include <vector>
#include <memory>        // For std::shared_ptr
#include <unordered_map> // To potentially cache retrieved data
#include <stdexcept>     // For std::runtime_error
#include <fstream>       // For file operations (basic storage implementation)
#include <filesystem>    // For directory creation/management (C++17)

// Include necessary headers from core for serialization
#include "../../src/core/transaction.h"
#include "../../src/core/finality_chain.h" // For Block definition

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for StorageManager-specific errors.
 */
class StorageError : public std::runtime_error {
public:
    explicit StorageError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 1. Storage Manager Interface
// ---------------------------

/**
 * Manages the persistent storage and retrieval of blockchain data (blocks, transactions, etc.).
 *
 * This is a simplified implementation using local files. In a real system,
 * this would interact with a robust database system (e.g., LevelDB, RocksDB, SQLite).
 */
class StorageManager {
private:
    std::string dataDirectory; // Path to the directory where data will be stored

    // Private helper for logging
    void log(const std::string& message) const;

    // Private helpers for path management
    std::string getBlockFilePath(const std::string& blockHash) const;
    std::string getTransactionFilePath(const std::string& txId) const;
    // ... potentially other file paths for UTXO set, validator state, etc.

public:
    /**
     * Constructor for StorageManager.
     * @param dir The directory path where blockchain data will be stored.
     */
    StorageManager(const std::string& dir);

    /**
     * Initializes the storage manager, ensuring the data directory exists.
     * @throws StorageError if the directory cannot be created or accessed.
     */
    void initialize();

    // --- Block Storage & Retrieval ---

    /**
     * Saves a block to persistent storage.
     * The block's data will be serialized and written to a file.
     * @param block A shared_ptr to the Block object to save.
     * @throws StorageError if serialization or file writing fails.
     */
    void saveBlock(std::shared_ptr<Block> block);

    /**
     * Loads a block from persistent storage by its hash.
     * @param blockHash The hash of the block to load.
     * @return A shared_ptr to the loaded Block object, or nullptr if not found.
     * @throws StorageError if deserialization or file reading fails.
     */
    std::shared_ptr<Block> loadBlock(const std::string& blockHash);

    /**
     * Checks if a block with the given hash exists in storage.
     * @param blockHash The hash of the block to check.
     * @return True if the block exists, false otherwise.
     */
    bool hasBlock(const std::string& blockHash) const;

    // --- Transaction Storage & Retrieval ---

    /**
     * Saves a transaction to persistent storage.
     * @param tx A shared_ptr to the Transaction object to save.
     * @throws StorageError if serialization or file writing fails.
     */
    void saveTransaction(std::shared_ptr<Transaction> tx);

    /**
     * Loads a transaction from persistent storage by its ID.
     * @param txId The ID of the transaction to load.
     * @return A shared_ptr to the loaded Transaction object, or nullptr if not found.
     * @throws StorageError if deserialization or file reading fails.
     */
    std::shared_ptr<Transaction> loadTransaction(const std::string& txId);

    /**
     * Checks if a transaction with the given ID exists in storage.
     * @param txId The ID of the transaction to check.
     * @return True if the transaction exists, false otherwise.
     */
    bool hasTransaction(const std::string& txId) const;

    // --- State Storage & Retrieval (e.g., UTXO set, chain tip) ---
    // These methods would be for saving and loading the overall state of the blockchain,
    // which is crucial for node startup and synchronization.

    /**
     * Saves the current UTXO set state.
     * This is an example; actual implementation might serialize the entire map or a diff.
     * @param utxos The current UTXO set.
     * @throws StorageError if saving fails.
     */
    void saveUtxoSet(const std::unordered_map<std::string, TransactionOutput>& utxos);

    /**
     * Loads the UTXO set state.
     * @return The loaded UTXO set.
     * @throws StorageError if loading fails or data is corrupted.
     */
    std::unordered_map<std::string, TransactionOutput> loadUtxoSet();

    /**
     * Saves the current chain tip hash and height.
     * @param tipHash The hash of the current chain tip block.
     * @param height The height of the current chain tip block.
     * @throws StorageError if saving fails.
     */
    void saveChainTip(const std::string& tipHash, std::int64_t height);

    /**
     * Loads the current chain tip hash and height.
     * @param tipHash Output parameter for the loaded tip hash.
     * @param height Output parameter for the loaded height.
     * @return True if tip found and loaded, false otherwise.
     * @throws StorageError if loading fails.
     */
    bool loadChainTip(std::string& tipHash, std::int64_t& height);

    // --- Cleanup/Utility ---

    /**
     * Clears all stored data from the data directory. Use with caution.
     */
    void clearAllData();
};

#endif // STORAGE_MANAGER_H