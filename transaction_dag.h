#ifndef TRANSACTION_DAG_H
#define TRANSACTION_DAG_H

#include <string>
#include <vector>
#include <unordered_map> // لتخزين المعاملات بواسطة الهاش الخاص بها
#include <unordered_set> // لتتبع المعاملات "الطرفية" (tips)
#include <memory>        // لاستخدام std::shared_ptr للمعاملات
#include <algorithm>     // لعمليات الفرز والبحث
#include <stdexcept>     // لاستخدام std::runtime_error

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
    // مفيد للتحقق من التبعيات وتحديد المعاملات النهائية
    std::unordered_map<std::string, std::vector<std::string>> childrenMap; // parent_tx_id -> list of child_tx_ids

    // تتبع العلاقات بين المعاملات (الابن -> الآباء)
    std::unordered_map<std::string, std::vector<std::string>> parentMap; // child_tx_id -> list of parent_tx_ids


    /**
     * Helper to update tips after a transaction is added.
     * If a new transaction refers to an existing tip, that tip is no longer a tip.
     * If the new transaction itself has no children yet, it becomes a new tip.
     * @param newTxId The ID of the newly added transaction.
     * @param parentTxIds The IDs of the parents of the new transaction.
     */
    void updateTips(const std::string& newTxId, const std::vector<std::string>& parentTxIds);

    /**
     * Helper to ensure that parent transactions actually exist in the DAG.
     * @param parentTxIds The IDs of the parent transactions.
     * @throws DAGError if any parent transaction is not found.
     */
    void validateParentExistence(const std::vector<std::string>& parentTxIds) const;

public:
    // Constructor
    TransactionDAG();

    /**
     * Adds a new transaction to the DAG.
     * Performs basic validation and updates the DAG structure (transactions map, tips).
     * @param tx A shared_ptr to the Transaction to add.
     * @throws DAGError if the transaction is invalid or already exists, or if parents are invalid.
     */
    void addTransaction(std::shared_ptr<Transaction> tx);

    /**
     * Retrieves a transaction from the DAG by its ID.
     * @param txId The ID of the transaction to retrieve.
     * @return A shared_ptr to the Transaction, or nullptr if not found.
     */
    std::shared_ptr<Transaction> getTransaction(const std::string& txId) const;

    /**
     * Removes a set of transactions from the DAG (e.g., after they are included in a block).
     * This also involves updating tips and parent/child relationships.
     * @param txIdsToRemove A set of transaction IDs to remove.
     * @throws DAGError if an invalid transaction ID is provided for removal.
     */
    void removeTransactions(const std::unordered_set<std::string>& txIdsToRemove);

    /**
     * Returns a list of current tips (transactions with no children in the DAG yet).
     * These are candidates for new transactions to reference.
     * @return A vector of strings representing the IDs of the current tips.
     */
    std::vector<std::string> getTips() const;

    /**
     * Checks if a transaction exists in the DAG.
     * @param txId The ID of the transaction to check.
     * @return True if the transaction exists, false otherwise.
     */
    bool containsTransaction(const std::string& txId) const;

    /**
     * Returns the number of transactions currently in the DAG.
     */
    size_t size() const;

    /**
     * Provides a count of the current tips in the DAG.
     */
    size_t getTipsCount() const;

    /**
     * Clears all transactions and tips from the DAG.
     * (Useful for testing or resetting state)
     */
    void clear();

    // Debugging/Utility methods (useful during development)
    void printDAGStatus() const;
};

#endif // TRANSACTION_DAG_H
