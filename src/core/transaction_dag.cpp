#include "transaction_dag.h"
#include <iostream>     // For use in debug printing functions
#include <queue>        // For BFS/topological sort in getTransactionsToProcess
#include <algorithm>    // For std::sort

// --- TransactionDAG Class Member Functions Implementation ---

// Constructor
TransactionDAG::TransactionDAG() {
    // Nothing special to initialize here, as maps and sets are initialized automatically.
}

// Helper function to update the "tips" of the DAG
void TransactionDAG::updateTips(const std::string& newTxId, const std::vector<std::string>& parentTxIds) {
    // 1. If the new transaction is the first in the DAG, it becomes the only tip.
    // This condition is checked only when adding the very first transaction.
    // In reality, if the DAG is empty, the first transaction will become a tip by default.
    // If the DAG already contains transactions, the new transaction must reference parents.
    if (transactions.size() == 1 && parentTxIds.empty()) { // This means it's the very first transaction
        tips.insert(newTxId);
        return;
    }

    // 2. Any parents referenced by the new transaction are no longer "tips"
    for (const std::string& parentId : parentTxIds) {
        // If the parent exists in the tips list, remove it
        tips.erase(parentId);
    }

    // 3. The new transaction itself becomes a "tip" because it has not been referenced as a parent yet
    // (unless it already has children, which shouldn't happen on initial addition).
    tips.insert(newTxId);
}

// Helper function to check for the existence of parent transactions
bool TransactionDAG::validateParentExistence(const std::vector<std::string>& parentTxIds) const {
    // If the DAG is empty, the first transaction (Coinbase or Genesis) doesn't need parents.
    // If the DAG is not empty, the new transaction must reference parents.
    if (transactions.empty()) {
        // If the first transaction has no parents, it's valid (could be a genesis transaction).
        // If it has parents in an empty DAG, it's a logical error (there can be no parents).
        if (!parentTxIds.empty()) {
            throw DAGError("First transaction in DAG cannot have parents.");
        }
        return true; // First transaction with no parents
    }
    else {
        // If the DAG is not empty, there must be parents.
        if (parentTxIds.empty()) {
            throw DAGError("New transaction must reference parent transactions in a non-empty DAG.");
        }
    }

    for (const std::string& parentId : parentTxIds) {
        if (transactions.find(parentId) == transactions.end()) {
            // If any of the parents are not found in the DAG
            return false; // We don't throw an exception here, but return false and let addTransaction decide.
        }
    }
    return true;
}

// Add a new transaction to the DAG
void TransactionDAG::addTransaction(std::shared_ptr<Transaction> tx,
    const std::unordered_map<std::string, TransactionOutput>& currentUtxoSet) {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent access

    if (!tx) {
        throw DAGError("Attempted to add a null transaction to DAG.");
    }
    const std::string& txId = tx->getId();

    // 1. Check if the transaction already exists
    if (transactions.count(txId)) {
        throw DAGError("Transaction already exists in DAG: " + txId);
    }

    // 2. Check for the existence of parent transactions in the DAG
    const std::vector<std::string>& parentTxIds = tx->getParents();
    // If this is the first transaction (DAG is empty) and it has no parents, it's valid.
    // Otherwise, all parent transactions must exist in the DAG or be confirmed (outside the scope of this DAG).
    // For the purpose of this DAG, we assume parents must exist here.
    if (!validateParentExistence(parentTxIds)) {
        throw DAGError("One or more parent transactions not found in DAG.");
    }

    // 3. Validate the transaction itself (using the transaction's own validate function)
    // This is where we use currentUtxoSet.
    // The validate function can throw a TransactionError
    if (!tx->getInputs().empty()) { // Coinbase transactions don't need UTXO validation
        if (!tx->validate(currentUtxoSet)) {
            // Transaction::validate will throw TransactionError itself if validation fails
            // This line might not be reached if validate throws
            throw TransactionError("Transaction validation failed for " + txId);
        }
    }

    // 4. Add the transaction to the main map
    transactions[txId] = tx;

    // 5. Update the children and parent maps
    for (const std::string& parentId : parentTxIds) {
        childrenMap[parentId].insert(txId);
        parentMap[txId].insert(parentId);
    }

    // 6. Update the list of tip transactions
    updateTips(txId, parentTxIds);

    // std::cout << "Transaction " << txId.substr(0, 8) << "... added to DAG. Tips count: " << tips.size() << std::endl;
}

// Retrieve a transaction from the DAG
std::shared_ptr<Transaction> TransactionDAG::getTransaction(const std::string& txId) const {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent read access
    auto it = transactions.find(txId);
    if (it != transactions.end()) {
        return it->second;
    }
    return nullptr; // Return a null pointer if the transaction is not found
}

// Remove a set of transactions from the DAG (after being included in a block)
void TransactionDAG::removeTransactions(const std::unordered_set<std::string>& txIdsToRemove) {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent access

    for (const std::string& txId : txIdsToRemove) {
        auto it = transactions.find(txId);
        if (it == transactions.end()) {
            std::cerr << "Warning: Attempted to remove non-existent transaction from DAG: " << txId << std::endl;
            continue;
        }

        // 1. Remove the transaction from the main map
        transactions.erase(it);

        // 2. Remove the transaction from the tips list (if it is a tip).
        // Note: If a transaction being removed was a tip, it means it was not referenced by any other transaction in the DAG.
        // If it had children, removing it would make them "unconfirmed" and require special handling.
        // But logically, when a transaction is removed from the DAG, it means it was confirmed in a block.
        // Therefore, it shouldn't be a tip.
        tips.erase(txId);

        // 3. Update the children and parent maps
        // First: update the children of this transaction (if it has any)
        // We must remove this transaction from the parent list of its children
        auto children_it = childrenMap.find(txId);
        if (children_it != childrenMap.end()) {
            for (const std::string& childId : children_it->second) {
                // Remove txId from the parent set of childId
                if (parentMap.count(childId)) {
                    parentMap[childId].erase(txId);
                    // If the child is now "orphaned" (has no confirmed parents in the DAG), we might need to handle it.
                    // In real DAG systems, children might point to multiple parents, some of which might confirm it.
                    // More complex logic would add these children to tips if all their parents
                    // become confirmed or are removed from the DAG.
                    // For now, we'll assume the child will remain in the DAG pointing to other parents if they exist.
                }
            }
            childrenMap.erase(txId); // Remove this transaction's entry from childrenMap
        }

        // Second: update the parents of this transaction (if it has any)
        // We must remove this transaction from the children list of its parents
        auto parent_of_removed_tx_it = parentMap.find(txId);
        if (parent_of_removed_tx_it != parentMap.end()) {
            for (const std::string& parentId : parent_of_removed_tx_it->second) {
                if (childrenMap.count(parentId)) {
                    childrenMap[parentId].erase(txId);
                    // If the parent no longer has any children in the DAG, it might become a new tip
                    if (childrenMap[parentId].empty()) {
                        tips.insert(parentId);
                    }
                }
            }
            parentMap.erase(txId); // Remove this transaction's entry from parentMap
        }
    }
}

// Get the list of tip transactions
std::vector<std::string> TransactionDAG::getTips() const {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent read access
    return std::vector<std::string>(tips.begin(), tips.end());
}

// Check if a transaction exists in the DAG
bool TransactionDAG::containsTransaction(const std::string& txId) const {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent read access
    return transactions.count(txId) > 0;
}

// Get the number of transactions in the DAG
size_t TransactionDAG::size() const {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent read access
    return transactions.size();
}

// Get the number of tips in the DAG
size_t TransactionDAG::getTipsCount() const {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent read access
    return tips.size();
}

// Clear all transactions from the DAG
void TransactionDAG::clear() {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent access
    transactions.clear();
    tips.clear();
    childrenMap.clear();
    parentMap.clear();
}

// Select transactions to be processed (for inclusion in a block)
std::vector<std::shared_ptr<Transaction>> TransactionDAG::getTransactionsToProcess(
    size_t maxTransactions,
    const std::unordered_map<std::string, double>& reputationScores) const {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent access

    std::vector<std::shared_ptr<Transaction>> selectedTransactions;
    if (transactions.empty()) {
        return selectedTransactions;
    }

    // We need to determine which transactions can be processed.
    // These are transactions whose parents are all either:
    // 1. Already present in the DAG.
    // 2. Or have already been processed (included in a previous block).
    // Here, we'll simplify and assume we are selecting "leaf" transactions in the current DAG
    // that have no parents missing from the DAG itself.
    // The most common approach is a Topological Sort of the transactions.

    // To simplify the selection process for now, we'll choose transactions that have no unconfirmed parents (within the DAG).
    // In a complex DAG system, you might need a more sophisticated selection algorithm (e.g., choosing the oldest, highest fee).

    // A simplified algorithm for selecting transactions (BFS-like approach)
    // 1. Calculate the "in-degree" for each transaction (number of its unconfirmed parents).
    // 2. Add transactions with in-degree = 0 (have no unconfirmed parents) to a queue.
    // 3. Process transactions from the queue:
    //    - Add the transaction to the list of selected transactions.
    //    - Decrement the in-degree of its children.
    //    - If a child's in-degree becomes 0, add it to the queue.

    std::unordered_map<std::string, int> inDegree;
    std::queue<std::string> q;

    // Initialize in-degree for all transactions in the DAG
    for (const auto& pair : transactions) {
        const std::string& txId = pair.first;
        if (parentMap.count(txId)) {
            inDegree[txId] = parentMap.at(txId).size();
        }
        else {
            inDegree[txId] = 0;
        }

        // If in-degree = 0, it means all its parents are either not in the DAG
        // (i.e., previously confirmed) or it's an initial transaction (no parents).
        if (inDegree[txId] == 0) {
            q.push(txId);
        }
    }

    while (!q.empty() && selectedTransactions.size() < maxTransactions) {
        std::string currentTxId = q.front();
        q.pop();

        if (transactions.count(currentTxId)) {
            selectedTransactions.push_back(transactions.at(currentTxId));
        }
        else {
            // This shouldn't happen if transactions and inDegree are synchronized
            continue;
        }

        // Decrement the in-degree for the children of the current transaction
        if (childrenMap.count(currentTxId)) {
            for (const std::string& childId : childrenMap.at(currentTxId)) {
                if (inDegree.count(childId)) { // Ensure the child is still in the DAG
                    inDegree[childId]--;
                    if (inDegree[childId] == 0) {
                        q.push(childId);
                    }
                }
            }
        }
    }

    // (New) Sort the final list based on reputation
    std::sort(selectedTransactions.begin(), selectedTransactions.end(),
        [&reputationScores](const std::shared_ptr<Transaction>& a, const std::shared_ptr<Transaction>& b) {
            // Find the reputation of each transaction's creator. If no reputation is recorded,
            // assign a default score (e.g., 100.0).
            double scoreA = reputationScores.count(a->getCreatorPublicKey()) ? reputationScores.at(a->getCreatorPublicKey()) : 100.0;
            double scoreB = reputationScores.count(b->getCreatorPublicKey()) ? reputationScores.at(b->getCreatorPublicKey()) : 100.0;

            // Sort so that higher reputation creators are at the front.
            return scoreA > scoreB;
        });

    // Return the prioritized list
    return selectedTransactions;
}

// Helper function for debugging: prints the status of the DAG
void TransactionDAG::printDAGStatus() const {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent read access
    std::cout << "\n--- DAG Status ---" << std::endl;
    std::cout << "Total Transactions in DAG: " << transactions.size() << std::endl;
    std::cout << "Current Tips Count: " << tips.size() << std::endl;

    if (!tips.empty()) {
        std::cout << "Current Tips (first 5):" << std::endl;
        int count = 0;
        for (const auto& tipId : tips) {
            std::cout << "  - " << tipId.substr(0, 10) << "..." << std::endl;
            count++;
            if (count >= 5) break;
        }
    }

    if (!transactions.empty()) {
        std::cout << "\nSample Transactions (first 5):" << std::endl;
        int count = 0;
        for (const auto& pair : transactions) {
            std::cout << "  Tx ID: " << pair.first.substr(0, 10) << "..." << std::endl;
            if (parentMap.count(pair.first) && !parentMap.at(pair.first).empty()) {
                std::cout << "    Parents: ";
                for (const auto& parentId : parentMap.at(pair.first)) {
                    std::cout << parentId.substr(0, 8) << "... ";
                }
                std::cout << std::endl;
            }
            if (childrenMap.count(pair.first) && !childrenMap.at(pair.first).empty()) {
                std::cout << "    Children: ";
                for (const auto& childId : childrenMap.at(pair.first)) {
                    std::cout << childId.substr(0, 8) << "... ";
                }
                std::cout << std::endl;
            }
            count++;
            if (count >= 5) break;
        }
    }
    std::cout << "--- End DAG Status ---\n" << std::endl;
}
