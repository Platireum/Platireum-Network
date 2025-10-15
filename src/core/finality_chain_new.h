#ifndef FINALITY_CHAIN_H
#define FINALITY_CHAIN_H

#include <string>
#include <vector>
#include <stdexcept>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "transaction.h" // For Transaction and TransactionOutput
#include "crypto_helper.h" // For hashing

/**
 * @brief Custom exception class for FinalityChain-specific errors.
 */
class FinalityChainError : public std::runtime_error {
public:
    explicit FinalityChainError(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @brief Represents a block in the FinalityChain.
 * This is a simplified representation for now, focusing on the transactions it finalizes.
 */
struct FinalityBlock {
    std::string blockHash; // Hash of this block
    std::string previousBlockHash; // Hash of the previous block in the chain
    std::vector<std::string> finalizedTransactionIds; // IDs of transactions finalized in this block
    std::string proposerPublicKey; // Public key of the validator who proposed this block
    long long timestamp; // Timestamp of block creation
    std::string signature; // Signature of the block by the proposer

    FinalityBlock(std::string hash, std::string prevHash, std::vector<std::string> txIds, std::string proposer, long long ts, std::string sig)
        : blockHash(std::move(hash)), previousBlockHash(std::move(prevHash)), finalizedTransactionIds(std::move(txIds)), proposerPublicKey(std::move(proposer)), timestamp(ts), signature(std::move(sig)) {}

    // Helper to get the data that needs to be signed/hashed for this block
    std::string toSignableString() const {
        std::string s = previousBlockHash + proposerPublicKey + std::to_string(timestamp);
        for (const auto& txId : finalizedTransactionIds) {
            s += txId;
        }
        return s;
    }
};

/**
 * @brief Manages the Finality Chain, a linear sequence of blocks that confirm transactions
 * from the TransactionDAG. This chain provides the final, irreversible order of transactions.
 */
class FinalityChain {
private:
    std::vector<std::shared_ptr<FinalityBlock>> chain; // The actual chain of blocks
    std::unordered_map<std::string, std::shared_ptr<FinalityBlock>> blockMap; // For quick lookup by blockHash
    std::mutex chainMutex; // Mutex for protecting shared data

public:
    FinalityChain();

    /**
     * @brief Adds a new block to the finality chain.
     * Performs validation to ensure the block is valid and extends the chain correctly.
     * @param newBlock A shared_ptr to the new FinalityBlock to add.
     * @throws FinalityChainError if the block is invalid (e.g., hash mismatch, invalid previous hash).
     */
    void addBlock(std::shared_ptr<FinalityBlock> newBlock);

    /**
     * @brief Retrieves a block from the chain by its hash.
     * @param blockHash The hash of the block to retrieve.
     * @return A shared_ptr to the FinalityBlock, or nullptr if not found.
     */
    std::shared_ptr<FinalityBlock> getBlock(const std::string& blockHash) const;

    /**
     * @brief Returns the latest block in the finality chain.
     * @return A shared_ptr to the latest FinalityBlock, or nullptr if the chain is empty.
     */
    std::shared_ptr<FinalityBlock> getLatestBlock() const;

    /**
     * @brief Returns the current height (number of blocks) of the finality chain.
     */
    size_t getHeight() const;

    /**
     * @brief Checks if a transaction has been finalized (included in any block in the chain).
     * @param transactionId The ID of the transaction to check.
     * @return True if the transaction is finalized, false otherwise.
     */
    bool isTransactionFinalized(const std::string& transactionId) const;

    /**
     * @brief Clears the entire finality chain (for testing or network reset).
     */
    void clear();

    // Debugging/Utility methods
    void printChainStatus() const;
};

#endif // FINALITY_CHAIN_H

