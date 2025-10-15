#include "transaction_dag.h"
#include <iostream>     // For use in debug printing functions
#include <cstddef>      // For std::size_t
#include <queue>        // For BFS/topological sort in getTransactionsToProcess
#include <algorithm>    // For std::sort

// --- TransactionDAG Class Member Functions Implementation ---

// Constructor
TransactionDAG::TransactionDAG(const FinalityChain& chain) : finalityChain(chain) {
    // Nothing special to initialize here, as maps and sets are initialized automatically.
}

// Helper function to update the "tips" of the DAG
void TransactionDAG::updateTips(const std::string& newTxId, const std::vector<std::string>& parentTxIds) {
    // 1. If the new transaction is the first in the DAG, it becomes the only tip.
    if (transactions.size() == 1 && parentTxIds.empty()) { // This means it's the very first transaction
        tips.insert(newTxId);
        return;
    }

    // 2. Any parents referenced by the new transaction are no longer "tips"
    for (const std::string& parentId : parentTxIds) {
        tips.erase(parentId);
    }

    // 3. The new transaction itself becomes a "tip"
    tips.insert(newTxId);
}

// Helper function to check for the existence of parent transactions
bool TransactionDAG::validateParentExistence(const std::vector<std::string>& parentTxIds) const {
    if (transactions.empty()) {
        if (!parentTxIds.empty()) {
            throw DAGError("First transaction in DAG cannot have parents.");
        }
        return true; 
    }
    else {
        if (parentTxIds.empty()) {
            throw DAGError("New transaction must reference parent transactions in a non-empty DAG.");
        }
    }

    for (const std::string& parentId : parentTxIds) {
        if (transactions.find(parentId) == transactions.end() && !isTransactionConfirmed(parentId)) {
            return false; 
        }
    }
    return true;
}

bool TransactionDAG::isTransactionConfirmed(const std::string& txId) const {
    return finalityChain.containsBlock(txId); // Assuming FinalityChain has a method to check for transaction confirmation by its ID.
}


// Add a new transaction to the DAG
void TransactionDAG::addTransaction(std::shared_ptr<Transaction> tx) {
    std::lock_guard<std::mutex> lock(dagMutex); // Protect concurrent access

    if (!tx) {
        throw DAGError("Attempted to add a null transaction to DAG.");
    }
    const std::string& txId = tx->getId();

    // 1. Check if the transaction already exists
    if (transactions.count(txId)) {
        throw DAGError("Transaction already exists in DAG: " + txId);
    }

    // 2. Check for the existence of parent transactions in the DAG or FinalityChain
    const std::vector<std::string>& parentTxIds = tx->getParents();
    if (!validateParentExistence(parentTxIds)) {
        throw DAGError("One or more parent transactions not found in DAG or FinalityChain.");
    }

    // 3. Validate the transaction itself (using the transaction's own validate function)
    if (!tx->getInputs().empty()) { // Coinbase transactions don't need UTXO validation
        if (!tx->validate(finalityChain.getUtxoSet())) {
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
        tips.erase(txId);

        // 3. Update the children and parent maps
        auto children_it = childrenMap.find(txId);
        if (children_it != childrenMap.end()) {
            for (const std::string& childId : children_it->second) {
                if (parentMap.count(childId)) {
                    parentMap[childId].erase(txId);
                }
            }
            childrenMap.erase(txId); 
        }

        auto parent_of_removed_tx_it = parentMap.find(txId);
        if (parent_of_removed_tx_it != parentMap.end()) {
            for (const std::string& parentId : parent_of_removed_tx_it->second) {
                if (childrenMap.count(parentId)) {
                    childrenMap[parentId].erase(txId);
                    if (childrenMap[parentId].empty()) {
                        tips.insert(parentId);
                    }
                }
            }
            parentMap.erase(txId); 
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

    std::unordered_map<std::string, int> inDegree;
    std::queue<std::string> q;

    for (const auto& pair : transactions) {
        const std::string& txId = pair.first;
        if (parentMap.count(txId)) {
            inDegree[txId] = parentMap.at(txId).size();
        }
        else {
            inDegree[txId] = 0;
        }

        if (inDegree[txId] == 0) {
            q.push(txId);
        }
    }

    while (!q.empty() && selectedTransactions.size() < maxTransactions) {
        std::string currentTxId = q.front();
        q.pop();

        selectedTransactions.push_back(transactions.at(currentTxId));

        if (childrenMap.count(currentTxId)) {
            for (const std::string& childId : childrenMap.at(currentTxId)) {
                inDegree[childId]--;
                if (inDegree[childId] == 0) {
                    q.push(childId);
                }
            }
        }
    }

    return selectedTransactions;
}

std::string TransactionDAG::calculateMerkleRoot(const std::vector<std::shared_ptr<Transaction>>& transactions) {
    if (transactions.empty()) {
        return CryptoHelper::sha256(""); // Merkle root of an empty set is hash of empty string
    }

    std::vector<std::string> hashes;
    for (const auto& tx : transactions) {
        hashes.push_back(tx->getId());
    }

    while (hashes.size() > 1) {
        if (hashes.size() % 2 != 0) {
            hashes.push_back(hashes.back()); // Duplicate last hash if odd number
        }
        std::vector<std::string> newHashes;
        for (size_t i = 0; i < hashes.size(); i += 2) {
            newHashes.push_back(CryptoHelper::sha256(hashes[i] + hashes[i+1]));
        }
        hashes = newHashes;
    }
    return hashes[0];
}

