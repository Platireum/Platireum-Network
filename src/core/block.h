#ifndef BLOCK_H
#define BLOCK_H

#include <string>
#include <vector>
#include <memory> // For std::shared_ptr
#include <chrono> // For timestamp
#include "transaction.h" // Block contains transactions

/**
 * @brief Represents a single block in the blockchain.
 * A block contains a header and a list of transactions.
 */
class Block {
private:
    std::string hash;             // Hash of this block (calculated from its contents)
    int height;                   // Block height in the chain
    std::string previousHash;     // Hash of the previous block
    std::string dagRootHash;      // Root hash of the Transaction DAG for transactions included in this block
    int nonce;                    // Nonce used for Proof-of-Work (PoW) or similar
    std::string minterId;         // ID of the node that mined/validated this block
    long long timestamp;          // Unix timestamp of block creation
    std::string signature;        // Signature of the block by the minter/validator

    std::vector<std::shared_ptr<Transaction>> transactions; // List of transactions included in this block

    // Helper to calculate the block's hash (internal to Block class)
    std::string calculateHash() const;

public:
    /**
     * @brief Constructor for Block.
     * @param hash The calculated hash of the block.
     * @param height The height of the block in the blockchain.
     * @param previousHash The hash of the previous block in the chain.
     * @param dagRootHash The root hash of the DAG of transactions included in this block.
     * @param nonce The nonce found during mining/validation.
     * @param minterId The ID of the minter/validator.
     * @param timestamp The timestamp of block creation.
     * @param signature The signature of the block by the minter/validator.
     */
    Block(const std::string& hash,
          int height,
          const std::string& previousHash,
          const std::string& dagRootHash,
          int nonce,
          const std::string& minterId,
          long long timestamp,
          const std::string& signature);

    // --- Getters ---
    const std::string& getHash() const { return hash; }
    int getHeight() const { return height; }
    const std::string& getPreviousHash() const { return previousHash; }
    const std::string& getDagRootHash() const { return dagRootHash; }
    int getNonce() const { return nonce; }
    const std::string& getMinterId() const { return minterId; }
    long long getTimestamp() const { return timestamp; }
    const std::string& getSignature() const { return signature; }
    const std::vector<std::shared_ptr<Transaction>>& getTransactions() const { return transactions; }

    // --- Setters (if needed, though blocks are usually immutable after creation) ---
    // void setHash(const std::string& h) { hash = h; } // Generally, hash is calculated, not set
    // void setSignature(const std::string& sig) { signature = sig; } // To be set after signing

    /**
     * @brief Adds a transaction to the block.
     * @param tx A shared_ptr to the Transaction to add.
     */
    void addTransaction(std::shared_ptr<Transaction> tx);

    /**
     * @brief Converts the block's data into a string for hashing or serialization.
     * @return A string representation of the block's essential data.
     */
    std::string toString() const;

    /**
     * @brief Serializes the block data to a JSON string.
     * This will be used for storage and API responses.
     * @return A JSON string representation of the block.
     */
    std::string serialize() const;

    /**
     * @brief Deserializes a JSON string into a Block object.
     * @param jsonString The JSON string representing a block.
     * @return A shared_ptr to the deserialized Block object.
     */
    static std::shared_ptr<Block> deserialize(const std::string& jsonString);
};

#endif // BLOCK_H