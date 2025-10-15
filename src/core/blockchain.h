#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <string>
#include <vector>
#include <memory>        // For std::shared_ptr
#include <unordered_map> // For UTXO set and block storage
#include <stdexcept>     // For std::runtime_error
#include <chrono>        // For timestamping blocks

#include "transaction.h"    // Needed for Transaction and UTXO definitions
#include "crypto_helper.h"  // Needed for hashing utilities

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for Block-specific errors.
 */
class BlockError : public std::runtime_error {
public:
    explicit BlockError(const std::string& msg) : std::runtime_error(msg) {}
};

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
 * Represents a Block in the Finality Chain.
 * Each block contains a header and a list of confirmed transactions.
 * It also references the previous block in the chain.
 */
// class Block {
private:
    std::string hash;               // The unique hash of this block
    std::string previousBlockHash;  // Hash of the previous block in the chain
    std::int64_t timestamp;         // Time when the block was created
    std::string validatorId;        // Public key of the validator who created this block
    std::string validatorSignature; // Signature of the validator on the block hash
    std::vector<std::string> transactionIds; // IDs of transactions confirmed in this block
    double totalFees;               // Sum of transaction fees in this block (reward for validator)

    // Private method to calculate the block's hash
    void calculateHash();

public:
    // Constructor for creating a new block (e.g., by a validator)
    Block(std::string prevHash,
          const std::string& valId,
          const CryptoHelper::ECKeyPtr& validatorPrivateKey,
          const std::vector<std::shared_ptr<Transaction>>& confirmedTransactions);

    // Constructor for loading an existing block (e.g., from storage or network)
    Block(std::string hash,
          std::string prevHash,
          std::int64_t ts,
          std::string valId,
          std::string valSignature,
          std::vector<std::string> txIds,
          double fees);

    /**
     * Validates the integrity of the block (e.g., hash, validator signature).
     * @param validatorPublicKeyHex The public key of the validator.
     * @return True if the block is valid, false otherwise.
     * @throws BlockError if validation fails.
     */
    bool validate(const std::string& validatorPublicKeyHex) const;

    // Getters for block data
    const std::string& getHash() const { return hash; }
    const std::string& getPreviousBlockHash() const { return previousBlockHash; }
    std::int64_t getTimestamp() const { return timestamp; }
    const std::string& getValidatorId() const { return validatorId; }
    const std::string& getValidatorSignature() const { return validatorSignature; }
    const std::vector<std::string>& getTransactionIds() const { return transactionIds; }
    double getTotalFees() const { return totalFees; }

    // Serialization for networking/storage (optional, can be done externally as well)
    std::string serialize() const;
    static std::shared_ptr<Block> deserialize(const std::string& data);
// };

// /**
//  * Manages the main Finality Blockchain.
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
                       bool isRevert = false);

public:
    // Constructor
    FinalityChain();

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

    // Utility/Debugging methods
    void printChainStatus() const;
    void clear(); // Clears the entire chain (for testing/reset)
};

#endif // BLOCKCHAIN_H
