#ifndef FINALITY_CHAIN_H
#define FINALITY_CHAIN_H

#include <string>
#include <vector>
#include <memory>        // For std::shared_ptr
#include <unordered_map> // For UTXO set and block storage
#include <stdexcept>     // For std::runtime_error
#include <chrono>        // For timestamping blocks
#include <mutex>         // For std::mutex

#include "block.h"          // Include the Block class definition
#include "validator_manager.h" // For ValidatorManager
#include "transaction.h"    // Needed for Transaction and UTXO definitions
#include "crypto_helper.h"  // Needed for hashing utilities

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for FinalityChain-specific errors.
 */
class FinalityChainError : public std::runtime_error {
public:
    explicit FinalityChainError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 4. Blockchain Component
// ---------------------------

/**
 * Manages the main Finality Blockchain.
 * Stores blocks, tracks the UTXO set, and handles adding/validating new blocks.
 */
class FinalityChain {
private:
    // Stores blocks in the chain, indexed by their hash
    std::unordered_map<std::string, std::shared_ptr<Block>> blocks;
    
    // The main chain's tip (the hash of the latest block)
    std::string currentChainTipHash;

    // Global UTXO set (Unspent Transaction Outputs)
    // This is the authoritative record of spendable funds.
    std::unordered_map<std::string, TransactionOutput> utxoSet;

    // A map to quickly look up block height by hash
    std::unordered_map<std::string, int> blockHeights; // block_hash -> height

    // A map to quickly look up block hash by height
    std::unordered_map<int, std::string> hashByHeight; // height -> block_hash

    // The current height of the blockchain
    int currentHeight;

    // Mutex for protecting shared data in a multi-threaded environment
    mutable std::mutex chainMutex;

    std::shared_ptr<ValidatorManager> validatorManager; // Reference to the ValidatorManager

    /**
     * Applies the effects of a block's transactions to the UTXO set.
     * Removes spent UTXOs and adds new ones.
     * @param block The block whose transactions are to be applied.
     * @param transactionsInBlock A map of actual Transaction objects referenced by the block.
     * @param isRevert If true, the operation is reverted (undoing the block's effects).
     * @throws FinalityChainError if UTXO update fails (e.g., trying to spend non-existent UTXO).
     */
    void updateUtxoSet(const Block& block, 
                       const std::unordered_map<std::string, std::shared_ptr<Transaction>>& transactionsInBlock,
                       bool isRevert,
                       std::unordered_map<std::string, TransactionOutput>& targetUtxoSet);

public:
    // Constructor
    FinalityChain(std::shared_ptr<ValidatorManager> vm);

    /**
     * Initializes the blockchain with a genesis block if it's empty.
     * @param validatorId The ID of the initial validator (for genesis block).
     * @param validatorPrivateKey The private key of the initial validator.
     * @throws FinalityChainError if genesis block creation fails.
     */
    void initializeGenesisBlock(const std::string& validatorId, const CryptoHelper::ECKeyPtr& validatorPrivateKey);

    /**
     * Adds a new block to the blockchain.
     * Validates the block, updates the UTXO set, and extends the chain.
     * @param newBlock A shared_ptr to the new Block to add.
     * @param transactionsInBlock A map of actual Transaction objects that are referenced in the new block.
     * These transactions should be retrieved from the DAG or other source.
     * @return True if the block was added successfully, false otherwise.
     * @throws FinalityChainError if block validation or UTXO update fails.
     */
    bool addBlock(std::shared_ptr<Block> newBlock,
                  const std::unordered_map<std::string, std::shared_ptr<Transaction>>& transactionsInBlock);

    /**
     * Returns the hash of the current chain tip.
     */
    const std::string& getCurrentChainTipHash() const { return currentChainTipHash; }

    /**
     * Returns the current height of the blockchain.
     */
    int getCurrentHeight() const { return currentHeight; }

    /**
     * Retrieves a block by its hash.
     * @param blockHash The hash of the block to retrieve.
     * @return A shared_ptr to the Block, or nullptr if not found.
     */
    std::shared_ptr<Block> getBlock(const std::string& blockHash) const;

    /**
     * Retrieves a block by its height.
     * @param height The height of the block to retrieve.
     * @return A shared_ptr to the Block, or nullptr if not found.
     */
    std::shared_ptr<Block> getBlockByHeight(int height) const;

    /**
     * Returns a const reference to the current UTXO set.
     * This set is critical for validating new transactions.
     */
    const std::unordered_map<std::string, TransactionOutput>& getUtxoSet() const { return utxoSet; }

    /**
     * Checks if a block exists in the chain.
     */
    bool containsBlock(const std::string& blockHash) const;

    /**
     * @brief Checks if a transaction exists in any block in the chain.
     * @param txId The ID of the transaction to check.
     * @return True if the transaction exists in a block, false otherwise.
     */
    bool containsTransaction(const std::string& txId) const;

    /**
     * @brief Returns a shared_ptr to the ValidatorManager.
     * @return The ValidatorManager instance.
     */
    std::shared_ptr<ValidatorManager> getValidatorManager() const { return validatorManager; }

    // Utility/Debugging methods
    void printChainStatus() const;
    void clear(); // Clears the entire chain (for testing/reset)
};

#endif // FINALITY_CHAIN_H

