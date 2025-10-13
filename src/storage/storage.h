#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include <string>
#include <vector>
#include <memory>        // For std::shared_ptr, std::unique_ptr
#include <unordered_map> // To potentially cache retrieved data
#include <stdexcept>     // For std::runtime_error
#include <fstream>       // For file operations (basic storage implementation)
#include <filesystem>    // For directory creation/management (C++17)

// Include necessary headers from core for serialization
#include "../../src/core/transaction.h"
#include "../../src/core/finality_chain.h" // For Block definition

// ---------------------------
// 0. IPFS Client Library Include
// ---------------------------
/**
 * Includes for IPFS client library.
 * In production environment, you would need to choose and install
 * a suitable C++ IPFS library. This is a hypothetical include.
 */
#include "ipfs/client.h"

 // ---------------------------
 // 1. Error Handling
 // ---------------------------
 /**
  * Custom exception class for StorageManager-specific errors.
  */
class StorageError : public std::runtime_error {
public:
    explicit StorageError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 2. Storage Manager Interface
// ---------------------------

/**
 * Manages the persistent storage and retrieval of blockchain data (blocks, transactions, etc.),
 * with support for both small data (like blockchain blocks) and large data (like AI model files)
 * using distributed storage (IPFS) for large blobs.
 *
 * This implementation uses local files for small metadata and IPFS for large data blobs.
 * In a real system, this would interact with a robust database system (e.g., LevelDB, RocksDB, SQLite).
 */
class StorageManager {
private:
    std::string dataDirectory; // Path to the directory where data will be stored

    /**
     * Smart pointer to IPFS client for distributed storage of large data blobs.
     * This allows each StorageManager to maintain its own connection to a local IPFS daemon.
     */
    std::unique_ptr<ipfs::Client> ipfsClient;

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
     * @param ipfsApiAddress The IPFS API address (defaults to localhost:5001).
     * @throws StorageError if IPFS client initialization fails.
     */
    StorageManager(const std::string& dir, const std::string& ipfsApiAddress = "/ip4/127.0.0.1/tcp/5001");

    /**
     * Initializes the storage manager, ensuring the data directory exists
     * and IPFS client is properly configured.
     * @throws StorageError if the directory cannot be created or accessed,
     *         or if IPFS connection fails.
     */
    void initialize();

    // --- Block Storage & Retrieval (Small Data - Local Storage) ---

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

    // --- Transaction Storage & Retrieval (Small Data - Local Storage) ---

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

    // --- Large Data Blob Storage & Retrieval (IPFS Distributed Storage) ---

    /**
     * @brief Saves a large data blob to the distributed storage (IPFS).
     * @param dataBlob The raw data to save.
     * @return The IPFS Content Identifier (CID) for the stored data.
     * @throws StorageError if IPFS operation fails.
     */
    std::string saveDataBlob(const std::vector<char>& dataBlob);

    /**
     * @brief Loads a data blob from IPFS using its CID.
     * @param cid The Content Identifier of the data to load.
     * @return A vector of chars containing the raw data.
     * @throws StorageError if IPFS operation fails or data is not found.
     */
    std::vector<char> loadDataBlob(const std::string& cid);

    /**
     * @brief Checks if a data blob with the given CID exists in IPFS storage.
     * @param cid The Content Identifier of the data to check.
     * @return True if the data exists in IPFS, false otherwise.
     * @throws StorageError if IPFS operation fails.
     */
    bool hasDataBlob(const std::string& cid);

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
     * Note: This only clears local storage, not IPFS distributed storage.
     */
    void clearAllData();

    /**
     * @brief Gets the IPFS client instance for advanced operations.
     * @return Reference to the IPFS client.
     */
    ipfs::Client& getIpfsClient() { return *ipfsClient; }
};

#endif // STORAGE_MANAGER_H
