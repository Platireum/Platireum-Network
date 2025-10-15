#ifndef TRANSACTION_DAG_H
#define TRANSACTION_DAG_H

#include <string>
#include <vector>
#include <unordered_map> // Used for storing transactions by their hash and for reputation scores
#include <unordered_set> // Used for tracking "tips"
#include <memory>        // Used for std::shared_ptr for transactions
#include <algorithm>     // Used for sorting and searching algorithms
#include <stdexcept>     // Used for std::runtime_error
#include <mutex>         // For std::mutex to protect shared data
#include "finality_chain.h" // Include the FinalityChain class definition

#include "transaction.h" // We need the definition of the Transaction class

// ---------------------------
// 0. Error Handling (can be defined here or in a separate general errors file)
// ---------------------------
/**
 * @brief Custom exception class for DAG-specific errors.
 */
class DAGError : public std::runtime_error {
public:
    explicit DAGError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 3. DAG Structure
// ---------------------------

/**
 * @brief Manages the Directed Acyclic Graph (DAG) of unconfirmed transactions.
 * Stores transactions and tracks their relationships (parents, children)
 * before they are confirmed and included in the main blockchain.
 */
class TransactionDAG {
private:
    // Reference to the FinalityChain to check for confirmed transactions
    const FinalityChain& finalityChain;
private:
    // Store all transactions in the DAG by their ID (transaction hash)
    std::unordered_map<std::string, std::shared_ptr<Transaction>> transactions;

    // Track "tips" - transactions that have not yet been referenced as a parent.
    // These are the transactions that new transactions can reference.
    std::unordered_set<std::string> tips;

    // Track relationships from parent to children
    std::unordered_map<std::string, std::unordered_set<std::string>> childrenMap; // parent_tx_id -> set of child_tx_ids

    // Track relationships from child to parents
    std::unordered_map<std::string, std::unordered_set<std::string>> parentMap; // child_tx_id -> set of parent_tx_ids

    // Mutex for protecting shared data in a multi-threaded environment
    mutable std::mutex dagMutex; // mutable allows locking in const methods if needed


    /**
     * @brief Helper to update tips after a transaction is added.
     * If a new transaction refers to an existing tip, that tip is no longer a tip.
     * If the new transaction itself has no children yet, it becomes a new tip.
     * @param newTxId The ID of the newly added transaction.
     * @param parentTxIds The IDs of the parents of the new transaction.
     */
    void updateTips(const std::string& newTxId, const std::vector<std::string>& parentTxIds);

    /**
     * @brief Helper to ensure that parent transactions actually exist in the DAG.
     * @param parentTxIds The IDs of the parent transactions.
     * @return True if all parents exist, false otherwise.
     * @throws DAGError if any parent transaction is not found.
     */
    bool validateParentExistence(const std::vector<std::string>& parentTxIds) const;

    // Helper to check if a transaction is already confirmed in the FinalityChain
    bool isTransactionConfirmed(const std::string& txId) const;

public:
    // Constructor
    TransactionDAG(const FinalityChain& chain);

    /**
     * @brief Adds a new transaction to the DAG.
     * Performs validation and updates the DAG structure (transactions map, tips).
     * @param tx A shared_ptr to the Transaction to add.
     * @param currentUtxoSet The current global UTXO set for transaction validation.
     * @throws DAGError if the transaction is invalid or already exists, or if parents are invalid.
     * @throws TransactionError if the transaction fails its internal validation.
     */
    void addTransaction(std::shared_ptr<Transaction> tx);

    /**
     * @brief Retrieves a transaction from the DAG by its ID.
     * @param txId The ID of the transaction to retrieve.
     * @return A shared_ptr to the Transaction, or nullptr if not found.
     */
    std::shared_ptr<Transaction> getTransaction(const std::string& txId) const;

    /**
     * @brief Removes a set of transactions from the DAG (e.g., after they are included in a block).
     * This also involves updating tips and parent/child relationships.
     * @param txIdsToRemove A set of transaction IDs to remove.
     * @throws DAGError if an invalid transaction ID is provided for removal.
     */
    void removeTransactions(const std::unordered_set<std::string>& txIdsToRemove);

    /**
     * @brief Returns a list of current tips (transactions with no children in the DAG yet).
     * These are candidates for new transactions to reference.
     * @return A vector of strings representing the IDs of the current tips.
     */
    std::vector<std::string> getTips() const;

    /**
     * @brief Checks if a transaction exists in the DAG.
     * @param txId The ID of the transaction to check.
     * @return True if the transaction exists, false otherwise.
     */
    bool containsTransaction(const std::string& txId) const;

    /**
     * @brief Returns the number of transactions currently in the DAG.
     */
    size_t size() const;

    /**
     * @brief Provides a count of the current tips in the DAG.
     */
    size_t getTipsCount() const;

    /**
     * @brief Clears all transactions and tips from the DAG.
     * (Useful for testing or resetting state)
     */
    void clear();

    /**
     * @brief Selects a set of transactions from the DAG for processing (e.g., to include in a new block).
     * This method is updated to accept reputation scores to allow for more sophisticated
     * transaction selection logic. For example, transactions from nodes with higher reputation
     * might be prioritized. The implementation of how these scores are used would be in the .cpp file.
     *
     * @param maxTransactions The maximum number of transactions to return.
     * @param reputationScores A map where the key is an identifier (e.g., node ID) and the value is its reputation score.
     * This data is passed from an external context (like the Node class) to influence transaction selection.
     * @return A vector of shared_ptr to transactions suitable for processing.
     */
    std::vector<std::shared_ptr<Transaction>> getTransactionsToProcess(
        size_t maxTransactions,
        const std::unordered_map<std::string, double>& reputationScores) const;

    /**
     * @brief Calculates the Merkle root of a given list of transactions.
     * @param transactions The list of transactions.
     * @return The Merkle root as a hexadecimal string.
     */
    static std::string calculateMerkleRoot(const std::vector<std::shared_ptr<Transaction>>& transactions);

    // Debugging/Utility methods (useful during development)
    void printDAGStatus() const;
};

#endif // TRANSACTION_DAG_H
