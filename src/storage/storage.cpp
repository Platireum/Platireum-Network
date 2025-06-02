#include "storage.h"
#include <iostream>
#include <fstream>      // For std::ifstream, std::ofstream
#include <sstream>      // For std::stringstream
#include <filesystem>   // For std::filesystem::create_directories, exists, remove (C++17)
#include <stdexcept>    // For std::runtime_error
#include <string>

// Include necessary headers from core for serialization/deserialization
#include "../../src/core/transaction.h" // For Transaction::serialize/deserialize
#include "../../src/core/finality_chain.h" // For Block::serialize/deserialize

namespace fs = std::filesystem; // Alias for easier use of filesystem library

// --- تنفيذ دوال فئة StorageManager ---

// Constructor
StorageManager::StorageManager(const std::string& dir) : dataDirectory(dir) {
    // Constructor primarily sets the data directory path.
    // Initialization (e.g., directory creation) happens in initialize().
}

// Simple logging utility for StorageManager
void StorageManager::log(const std::string& message) const {
    std::cout << "[StorageManager] " << message << std::endl;
}

// Get file path for a block
std::string StorageManager::getBlockFilePath(const std::string& blockHash) const {
    return dataDirectory + "/blocks/" + blockHash + ".json";
}

// Get file path for a transaction
std::string StorageManager::getTransactionFilePath(const std::string& txId) const {
    return dataDirectory + "/transactions/" + txId + ".json";
}

// Get file path for UTXO set
std::string StorageManager::getUtxoSetFilePath() const {
    return dataDirectory + "/utxo_set.json";
}

// Get file path for chain tip
std::string StorageManager::getChainTipFilePath() const {
    return dataDirectory + "/chain_tip.txt";
}

// Initialize storage manager, ensure directories exist
void StorageManager::initialize() {
    try {
        if (!fs::exists(dataDirectory)) {
            fs::create_directories(dataDirectory);
            log("Created data directory: " + dataDirectory);
        }
        if (!fs::exists(dataDirectory + "/blocks")) {
            fs::create_directories(dataDirectory + "/blocks");
            log("Created blocks directory: " + dataDirectory + "/blocks");
        }
        if (!fs::exists(dataDirectory + "/transactions")) {
            fs::create_directories(dataDirectory + "/transactions");
            log("Created transactions directory: " + dataDirectory + "/transactions");
        }
        log("StorageManager initialized successfully. Data path: " + dataDirectory);
    } catch (const fs::filesystem_error& e) {
        throw StorageError("Failed to initialize storage directories: " + std::string(e.what()));
    }
}

---

### Block Storage & Retrieval

void StorageManager::saveBlock(std::shared_ptr<Block> block) {
    if (!block) {
        throw StorageError("Attempted to save a nullptr block.");
    }
    std::string filePath = getBlockFilePath(block->getHash());
    try {
        std::ofstream outFile(filePath);
        if (!outFile.is_open()) {
            throw StorageError("Failed to open file for writing block: " + filePath);
        }
        outFile << block->serialize(); // Serialize the block to a string and write
        outFile.close();
        // log("Saved block: " + block->getHash().substr(0, 8) + "...");
    } catch (const std::exception& e) {
        throw StorageError("Error saving block " + block->getHash().substr(0, 8) + "...: " + std::string(e.what()));
    }
}

std::shared_ptr<Block> StorageManager::loadBlock(const std::string& blockHash) {
    std::string filePath = getBlockFilePath(blockHash);
    if (!fs::exists(filePath)) {
        // log("Block not found: " + blockHash.substr(0, 8) + "...");
        return nullptr; // Block not found
    }
    try {
        std::ifstream inFile(filePath);
        if (!inFile.is_open()) {
            throw StorageError("Failed to open file for reading block: " + filePath);
        }
        std::stringstream buffer;
        buffer << inFile.rdbuf(); // Read entire file content
        inFile.close();
        return Block::deserialize(buffer.str()); // Deserialize the string content
    } catch (const std::exception& e) {
        throw StorageError("Error loading block " + blockHash.substr(0, 8) + "...: " + std::string(e.what()));
    }
}

bool StorageManager::hasBlock(const std::string& blockHash) const {
    return fs::exists(getBlockFilePath(blockHash));
}

---

### Transaction Storage & Retrieval

void StorageManager::saveTransaction(std::shared_ptr<Transaction> tx) {
    if (!tx) {
        throw StorageError("Attempted to save a nullptr transaction.");
    }
    std::string filePath = getTransactionFilePath(tx->getId());
    try {
        std::ofstream outFile(filePath);
        if (!outFile.is_open()) {
            throw StorageError("Failed to open file for writing transaction: " + filePath);
        }
        outFile << tx->serialize(); // Serialize the transaction to a string and write
        outFile.close();
        // log("Saved transaction: " + tx->getId().substr(0, 8) + "...");
    } catch (const std::exception& e) {
        throw StorageError("Error saving transaction " + tx->getId().substr(0, 8) + "...: " + std::string(e.what()));
    }
}

std::shared_ptr<Transaction> StorageManager::loadTransaction(const std::string& txId) {
    std::string filePath = getTransactionFilePath(txId);
    if (!fs::exists(filePath)) {
        // log("Transaction not found: " + txId.substr(0, 8) + "...");
        return nullptr; // Transaction not found
    }
    try {
        std::ifstream inFile(filePath);
        if (!inFile.is_open()) {
            throw StorageError("Failed to open file for reading transaction: " + filePath);
        }
        std::stringstream buffer;
        buffer << inFile.rdbuf(); // Read entire file content
        inFile.close();
        return Transaction::deserialize(buffer.str()); // Deserialize the string content
    } catch (const std::exception& e) {
        throw StorageError("Error loading transaction " + txId.substr(0, 8) + "...: " + std::string(e.what()));
    }
}

bool StorageManager::hasTransaction(const std::string& txId) const {
    return fs::exists(getTransactionFilePath(txId));
}

---

### State Storage & Retrieval (UTXO Set, Chain Tip)

// Helper to serialize UTXO set (simple JSON-like string)
std::string serializeUtxoSet(const std::unordered_map<std::string, TransactionOutput>& utxos) {
    std::string serializedData = "{";
    bool first = true;
    for (const auto& pair : utxos) {
        if (!first) serializedData += ",";
        serializedData += "\"" + pair.first + "\":" + pair.second.serialize();
        first = false;
    }
    serializedData += "}";
    return serializedData;
}

// Helper to deserialize UTXO set (simple JSON-like string)
std::unordered_map<std::string, TransactionOutput> deserializeUtxoSet(const std::string& data) {
    std::unordered_map<std::string, TransactionOutput> utxos;
    // This is a very basic parsing. A robust solution would use a JSON parsing library.
    // This assumes format {"utxo_id1":{tx_output_json1}, "utxo_id2":{tx_output_json2}}
    if (data.length() < 2 || data.front() != '{' || data.back() != '}') {
        throw StorageError("Invalid UTXO set data format (not enclosed in {}).");
    }
    std::string inner_data = data.substr(1, data.length() - 2); // Remove outer braces

    std::stringstream ss(inner_data);
    std::string segment;
    while(std::getline(ss, segment, ',')) {
        size_t colon_pos = segment.find(':');
        if (colon_pos == std::string::npos) continue;

        std::string key_str = segment.substr(0, colon_pos);
        // Remove quotes if present
        if (key_str.length() >= 2 && key_str.front() == '"' && key_str.back() == '"') {
            key_str = key_str.substr(1, key_str.length() - 2);
        }

        std::string value_str = segment.substr(colon_pos + 1);
        try {
            TransactionOutput utxo_output = TransactionOutput::deserialize(value_str);
            utxos[utxo_output.getId()] = utxo_output;
        } catch (const std::exception& e) {
            throw StorageError("Error deserializing UTXO entry: " + std::string(e.what()));
        }
    }
    return utxos;
}

void StorageManager::saveUtxoSet(const std::unordered_map<std::string, TransactionOutput>& utxos) {
    std::string filePath = getUtxoSetFilePath();
    try {
        std::ofstream outFile(filePath);
        if (!outFile.is_open()) {
            throw StorageError("Failed to open file for writing UTXO set: " + filePath);
        }
        outFile << serializeUtxoSet(utxos);
        outFile.close();
        // log("Saved UTXO set with " + std::to_string(utxos.size()) + " entries.");
    } catch (const std::exception& e) {
        throw StorageError("Error saving UTXO set: " + std::string(e.what()));
    }
}

std::unordered_map<std::string, TransactionOutput> StorageManager::loadUtxoSet() {
    std::string filePath = getUtxoSetFilePath();
    if (!fs::exists(filePath)) {
        // log("UTXO set file not found. Returning empty set.");
        return {}; // Return empty set if file doesn't exist
    }
    try {
        std::ifstream inFile(filePath);
        if (!inFile.is_open()) {
            throw StorageError("Failed to open file for reading UTXO set: " + filePath);
        }
        std::stringstream buffer;
        buffer << inFile.rdbuf();
        inFile.close();
        return deserializeUtxoSet(buffer.str());
    } catch (const std::exception& e) {
        throw StorageError("Error loading UTXO set: " + std::string(e.what()));
    }
}

void StorageManager::saveChainTip(const std::string& tipHash, std::int64_t height) {
    std::string filePath = getChainTipFilePath();
    try {
        std::ofstream outFile(filePath);
        if (!outFile.is_open()) {
            throw StorageError("Failed to open file for writing chain tip: " + filePath);
        }
        outFile << tipHash << "\n" << height; // Hash on first line, height on second
        outFile.close();
        // log("Saved chain tip: " + tipHash.substr(0, 8) + "... at height " + std::to_string(height));
    } catch (const std::exception& e) {
        throw StorageError("Error saving chain tip: " + std::string(e.what()));
    }
}

bool StorageManager::loadChainTip(std::string& tipHash, std::int64_t& height) {
    std::string filePath = getChainTipFilePath();
    if (!fs::exists(filePath)) {
        // log("Chain tip file not found.");
        return false; // Chain tip not found
    }
    try {
        std::ifstream inFile(filePath);
        if (!inFile.is_open()) {
            throw StorageError("Failed to open file for reading chain tip: " + filePath);
        }
        std::string hash_str;
        std::string height_str;
        if (std::getline(inFile, hash_str) && std::getline(inFile, height_str)) {
            tipHash = hash_str;
            height = std::stoll(height_str);
            inFile.close();
            // log("Loaded chain tip: " + tipHash.substr(0, 8) + "... at height " + std::to_string(height));
            return true;
        }
        inFile.close();
        throw StorageError("Invalid chain tip file format.");
    } catch (const std::exception& e) {
        throw StorageError("Error loading chain tip: " + std::string(e.what()));
    }
}

---

### Cleanup/Utility

void StorageManager::clearAllData() {
    try {
        if (fs::exists(dataDirectory)) {
            fs::remove_all(dataDirectory); // Recursively remove directory and its contents
            log("Cleared all data from: " + dataDirectory);
        }
    } catch (const fs::filesystem_error& e) {
        throw StorageError("Failed to clear data directory: " + std::string(e.what()));
    }
}