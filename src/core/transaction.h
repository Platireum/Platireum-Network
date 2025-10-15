#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set> // For std::unordered_set

#include "crypto_helper.h"
#include "../ai_engine/ai_engine.h" // For AIEngine::ProofOfComputation
#include <nlohmann/json.hpp> // For JSON serialization/deserialization

// Use nlohmann::json for JSON operations
using json = nlohmann::json;

// Forward declarations
class Transaction;

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for transaction errors
 */
class TransactionError : public std::runtime_error {
public:
    explicit TransactionError(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @brief Represents an input to a transaction.
 * An input references an output from a previous transaction (UTXO).
 */
struct TransactionInput {
    std::string transactionId; // ID of the transaction containing the UTXO being spent
    int outputIndex;           // Index of the UTXO in the referenced transaction's outputs
    std::string signature;     // Signature by the owner of the UTXO
    std::string publicKey;     // Public key of the owner of the UTXO

    // For hashing and comparison
    std::string toString() const {
        return transactionId + std::to_string(outputIndex) + publicKey;
    }

    bool operator==(const TransactionInput& other) const {
        return transactionId == other.transactionId &&
               outputIndex == other.outputIndex &&
               signature == other.signature &&
               publicKey == other.publicKey;
    }

    // nlohmann/json serialization
    friend void to_json(json& j, const TransactionInput& p) {
        j = json{{"transactionId", p.transactionId}, {"outputIndex", p.outputIndex}, {"signature", p.signature}, {"publicKey", p.publicKey}};
    }

    // nlohmann/json deserialization
    friend void from_json(const json& j, TransactionInput& p) {
        j.at("transactionId").get_to(p.transactionId);
        j.at("outputIndex").get_to(p.outputIndex);
        j.at("signature").get_to(p.signature);
        j.at("publicKey").get_to(p.publicKey);
    }
};

/**
 * @brief Represents an output of a transaction.
 * An output specifies an amount and the recipient's public key.
 */
struct TransactionOutput {
    std::string recipientPublicKey; // Public key of the recipient
    double amount;                  // Amount of currency

    TransactionOutput() : recipientPublicKey(""), amount(0.0) {}
    TransactionOutput(const std::string& pubKey, double val) : recipientPublicKey(pubKey), amount(val) {}

    // For hashing and comparison
    std::string toString() const {
        return recipientPublicKey + std::to_string(amount);
    }

    bool operator==(const TransactionOutput& other) const {
        return recipientPublicKey == other.recipientPublicKey &&
               amount == other.amount;
    }

    // nlohmann/json serialization
    friend void to_json(json& j, const TransactionOutput& p) {
        j = json{{"recipientPublicKey", p.recipientPublicKey}, {"amount", p.amount}};
    }

    // nlohmann/json deserialization
    friend void from_json(const json& j, TransactionOutput& p) {
        j.at("recipientPublicKey").get_to(p.recipientPublicKey);
        j.at("amount").get_to(p.amount);
    }
};

/**
 * @brief Enum for different types of transactions.
 */
enum class TransactionType {
    VALUE_TRANSFER,             // Standard value transfer transaction
    SMART_CONTRACT_CALL, // Transaction to call a smart contract function
    AI_COMPUTATION_PROOF // Transaction to submit AI computation proof
};

/**
 * @brief Represents a single transaction in the blockchain.
 */
class Transaction {
private:
    std::string id;                         // Unique hash of this transaction
    TransactionType type;                   // Type of transaction
    long long timestamp;                    // Unix timestamp of transaction creation
    std::string creatorPublicKey;           // Public key of transaction creator
    std::string payload;                    // Transaction-specific data in JSON format
    std::vector<std::string> parentTxs;    // References to parent transactions in DAG structure
    std::string signature;                  // Signature of transaction creator
    AIEngine::ProofOfComputation aiProof;   // AI computation proof, if type is AI_COMPUTATION_PROOF

    // Helper to calculate the transaction's ID (hash)
    std::string calculateId();

public:
    // Constructor for building a new transaction with flexible payload
    Transaction(TransactionType txType,
                const std::string& creatorPubKey,
                const std::string& dataPayload = "",
                const std::vector<std::string>& parents = {},
                const AIEngine::ProofOfComputation& proof = {});

    // Constructor for deserializing or recreating an already signed transaction
    Transaction(std::string id,
                TransactionType txType,
                long long ts,
                std::string creatorPubKey,
                std::string dataPayload,
                std::vector<std::string> parents,
                std::string sig,
                AIEngine::ProofOfComputation proof);

    // Sign the transaction with private key
    void sign(const CryptoHelper::ECKeyPtr& privateKey);

    // Verify the transaction signature
    bool verifySignature() const;

    // Validate the transaction (signatures, amounts, etc.)
    bool validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const;

    // --- Getters ---
    const std::string& getId() const { return id; }
    TransactionType getType() const { return type; }
    long long getTimestamp() const { return timestamp; }
    const std::string& getCreatorPublicKey() const { return creatorPublicKey; }
    const std::string& getPayload() const { return payload; }
    const std::vector<std::string>& getParents() const { return parentTxs; }
    const std::string& getSignature() const { return signature; }
    const AIEngine::ProofOfComputation& getAIProof() const { return aiProof; }

    // For value transfer transactions
    const std::vector<TransactionInput>& getInputs() const;
    const std::vector<TransactionOutput>& getOutputs() const;

    // --- Setters ---
    void setPayload(const std::string& newPayload);

    // Get a hash of the transaction's content for signing inputs
    std::string getHashForSigningInputs() const;

    // Helper method to create a signed TransactionInput for financial transactions
    static TransactionInput createSignedInput(
        const std::string& utxoId,
        const CryptoHelper::ECKeyPtr& privateKey,
        const std::string& currentTxId
    );

    // Serializes the transaction data to a JSON string
    std::string serialize() const;

    // Deserializes a JSON string into a Transaction object
    static std::shared_ptr<Transaction> deserialize(const std::string& jsonString);

    // Provides a human-readable string representation of the transaction
    std::string toString() const;

    // Converts TransactionType enum to string representation
    static std::string transactionTypeToString(TransactionType type);

    // Converts string to TransactionType enum
    static TransactionType stringToTransactionType(const std::string& typeStr);
};

#endif // TRANSACTION_H

