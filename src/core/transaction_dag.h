#ifndef TRANSACTION_DAG_H
#define TRANSACTION_DAG_H

#include <string>
#include <vector>
#include <unordered_map> // لتخزين المعاملات بواسطة الهاش الخاص بها
#include <unordered_set> // لتتبع المعاملات "الطرفية" (tips)
#include <memory>        // لاستخدام std::shared_ptr للمعاملات
#include <algorithm>     // لعمليات الفرز والبحث
#include <stdexcept>     // لاستخدام std::runtime_error
#include <mutex>         // For std::mutex to protect shared data

#include "transaction.h" // نحتاج لتعريف فئة Transaction

// ---------------------------
// 0. Error Handling (يمكن تعريفها هنا أو في ملف منفصل للأخطاء العامة)
// ---------------------------
/**
 * Custom exception class for DAG-specific errors
 */
class DAGError : public std::runtime_error {
public:
    explicit DAGError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 3. DAG Structure
// ---------------------------

/**
 * Manages the Directed Acyclic Graph (DAG) of unconfirmed transactions.
 * Stores transactions and tracks their relationships (parents, children)
 * before they are confirmed and included in the main blockchain.
 */
class TransactionDAG {
private:
    // تخزين جميع المعاملات في الـ DAG بواسطة معرفها (هاش المعاملة)
    std::unordered_map<std::string, std::shared_ptr<Transaction>> transactions;
    
    // تتبع المعاملات "الطرفية" (tips) - وهي المعاملات التي لم يتم الإشارة إليها كـ "أب" بعد
    // هذه هي المعاملات التي يمكن أن تشير إليها المعاملات الجديدة.
    std::unordered_set<std::string> tips;

    // تتبع العلاقات بين المعاملات (الأب -> الأبناء)
    std::unordered_map<std::string, std::unordered_set<std::string>> childrenMap; // parent_tx_id -> set of child_tx_ids (using set for faster removal)

    // تتبع العلاقات بين المعاملات (الابن -> الآباء)
    std::unordered_map<std::string, std::unordered_set<std::string>> parentMap; // child_tx_id -> set of parent_tx_ids

    // Mutex لحماية البيانات المشتركة في بيئة متعددة الخيوط
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
     * @throws DAGError if any parent transaction is not found and the DAG is not empty.
     */
    bool validateParentExistence(const std::vector<std::string>& parentTxIds) const;

public:
    // Constructor
    TransactionDAG();

    /**
     * @brief Adds a new transaction to the DAG.
     * Performs basic validation and updates the DAG structure (transactions map, tips).
     * The transaction's internal validity (signatures, amounts) is checked
     * against the provided UTXO set.
     * @param tx A shared_ptr to the Transaction to add.
     * @param currentUtxoSet The current global UTXO set for transaction validation.
     * @throws DAGError if the transaction is invalid or already exists, or if parents are invalid.
     * @throws TransactionError if the transaction fails its internal validation.
     */
    void addTransaction(std::shared_ptr<Transaction> tx,
                        const std::unordered_map<std::string, TransactionOutput>& currentUtxoSet);

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
     * @brief Selects a set of transactions from the DAG that can be included in a new block.
     * This typically involves selecting transactions whose all parents are either already
     * confirmed or present within the current DAG (and thus will be confirmed with the block).
     * This method might also prioritize transactions (e.g., by fee or age).
     * @param maxTransactions The maximum number of transactions to return.
     * @return A vector of shared_ptr to transactions suitable for block inclusion.
     */
    std::vector<std::shared_ptr<Transaction>> getTransactionsToProcess(size_t maxTransactions = 100) const;

    // Debugging/Utility methods (useful during development)
    void printDAGStatus() const;
};

#endif // TRANSACTION_DAG_H