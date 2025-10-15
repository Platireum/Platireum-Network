#include "block.h"
#include <iostream> // For std::cerr
#include <sstream>
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <nlohmann/json.hpp> // For JSON serialization/deserialization

// Use nlohmann::json for JSON operations
using json = nlohmann::json;

// --- Block Class Member Functions Implementation ---

// Constructor for creating a new block (used by validator/miner)
Block::Block(std::string previousBlockHash,
             int height,
             std::string dagRootHash,
             std::string validatorId,
             const CryptoHelper::ECKeyPtr& validatorPrivateKey,
             const std::vector<std::shared_ptr<Transaction>>& confirmedTransactions)
    : previousBlockHash(std::move(previousBlockHash)),
      height(height),
      dagRootHash(std::move(dagRootHash)),
      timestamp(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()),
      validatorId(std::move(validatorId))
{
    // Extract transaction IDs
    for (const auto& tx : confirmedTransactions) {
        transactionIds.push_back(tx->getId());
    }

    calculateHash(); // Calculate hash based on initial content
    sign(validatorPrivateKey); // Sign the block with the validator's private key
}

// Constructor for deserializing or recreating an existing block
Block::Block(std::string hash_val,
             std::string previousBlockHash_val,
             int height_val,
             std::string dagRootHash_val,
             long long ts,
             std::string validatorId_val,
             std::string validatorSignature_val,
             const std::vector<std::string>& txIds)
    : hash(std::move(hash_val)),
      previousBlockHash(std::move(previousBlockHash_val)),
      height(height_val),
      dagRootHash(std::move(dagRootHash_val)),
      timestamp(ts),
      validatorId(std::move(validatorId_val)),
      validatorSignature(std::move(validatorSignature_val)),
      transactionIds(txIds)
{
    // No hash calculation or signing needed here, as it's for an existing block
    // We can optionally re-validate the hash and signature here if needed
}

// Helper to calculate the block's hash
void Block::calculateHash() {
    std::stringstream ss;
    ss << previousBlockHash << height << dagRootHash << timestamp << validatorId;
    for (const auto& txId : transactionIds) {
        ss << txId;
    }
    hash = CryptoHelper::sha256(ss.str());
}

// Sign the block with the validator's private key
void Block::sign(const CryptoHelper::ECKeyPtr& privateKey) {
    if (hash.empty()) {
        calculateHash(); // Ensure hash is calculated before signing
    }
    std::vector<unsigned char> signatureBytes = CryptoHelper::signData(privateKey, hash);
    validatorSignature = CryptoHelper::bytesToHex(signatureBytes);
}

// Validate the block (hash, signature, etc.)
bool Block::validate(const std::string& validatorPublicKeyHex) const {
    // 1. Verify hash integrity
    std::stringstream ss;
    ss << previousBlockHash << height << dagRootHash << timestamp << validatorId;
    for (const auto& txId : transactionIds) {
        ss << txId;
    }
    std::string calculatedHash = CryptoHelper::sha256(ss.str());
    if (calculatedHash != hash) {
        std::cerr << "Block validation failed: Hash mismatch for block " << hash.substr(0, 8) << "..." << std::endl;
        return false;
    }

    // 2. Verify validator signature
    if (validatorId.empty() || validatorSignature.empty()) {
        std::cerr << "Block validation failed: Validator ID or signature is empty for block " << hash.substr(0, 8) << "..." << std::endl;
        return false;
    }
    // We need the public key of the validator to verify the signature.
    // In a real system, this would be looked up from a registry or derived from the validatorId.
    // For now, we assume validatorId is the public key itself or can be used to retrieve it.
    // This is a simplification; CryptoHelper::verifySignature expects a public key string.
    if (!CryptoHelper::verifySignature(validatorPublicKeyHex, CryptoHelper::hexToBytes(validatorSignature), hash)) {
        std::cerr << "Block validation failed: Invalid validator signature for block " << hash.substr(0, 8) << "..." << std::endl;
        return false;
    }

    // Further validation (e.g., transaction validity, DAG consistency) would happen at a higher level (e.g., FinalityChain)
    return true;
}

// Serializes the block data to a JSON string
std::string Block::serialize() const {
    json j;
    j["hash"] = hash;
    j["previousBlockHash"] = previousBlockHash;
    j["height"] = height;
    j["dagRootHash"] = dagRootHash;
    j["timestamp"] = timestamp;
    j["validatorId"] = validatorId;
    j["validatorSignature"] = validatorSignature;
    j["transactionIds"] = transactionIds;
    return j.dump();
}

// Deserializes a JSON string into a Block object
std::shared_ptr<Block> Block::deserialize(const std::string& jsonString) {
    try {
        json j = json::parse(jsonString);
        std::string hash_val = j.at("hash").get<std::string>();
        std::string previousBlockHash_val = j.at("previousBlockHash").get<std::string>();
        int height_val = j.at("height").get<int>();
        std::string dagRootHash_val = j.at("dagRootHash").get<std::string>();
        long long timestamp_val = j.at("timestamp").get<long long>();
        std::string validatorId_val = j.at("validatorId").get<std::string>();
        std::string validatorSignature_val = j.at("validatorSignature").get<std::string>();
        std::vector<std::string> transactionIds_val = j.at("transactionIds").get<std::vector<std::string>>();

        return std::make_shared<Block>(hash_val, previousBlockHash_val, height_val, dagRootHash_val,
                                     timestamp_val, validatorId_val, validatorSignature_val, transactionIds_val);
    } catch (const json::parse_error& e) {
        std::cerr << "JSON parse error in Block::deserialize: " << e.what() << std::endl;
        return nullptr;
    } catch (const std::exception& e) {
        std::cerr << "Error in Block::deserialize: " << e.what() << std::endl;
        return nullptr;
    }
}

// Provides a human-readable string representation of the block
std::string Block::toString() const {
    std::stringstream ss;
    ss << "Block Hash: " << hash.substr(0, 16) << "...\n"
       << "  Previous Hash: " << previousBlockHash.substr(0, 16) << "...\n"
       << "  Height: " << height << "\n"
       << "  DAG Root Hash: " << dagRootHash.substr(0, 16) << "...\n"
       << "  Timestamp: " << timestamp << "\n"
       << "  Validator ID: " << validatorId.substr(0, 16) << "...\n"
       << "  Signature: " << validatorSignature.substr(0, 16) << "...\n"
       << "  Transactions (" << transactionIds.size() << "):\n";
    for (const auto& txId : transactionIds) {
        ss << "    - " << txId.substr(0, 16) << "...\n";
    }
    return ss.str();
}

