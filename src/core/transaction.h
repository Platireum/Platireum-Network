#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <vector>
#include <unordered_map> // For UTXO Set usage later
#include <unordered_set> // For preventing UTXO double spending within transaction
#include <chrono>        // For timestamp
#include <sstream>       // For string building
#include <iomanip>       // For formatting
#include <memory>        // For std::shared_ptr

#include "crypto_helper.h" // We need crypto functions for hash and signature

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
 * Custom exception class for ledger errors (or general ledger errors)
 */
class LedgerError : public std::runtime_error {
public:
    explicit LedgerError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 1. Transaction Type Enum
// ---------------------------
/**
 * Enumeration for different transaction types to make the network "smart"
 * and capable of understanding the context of each operation.
 */
enum class TransactionType {
    VALUE_TRANSFER,     // For value transfer (current use case)
    INFERENCE_REQUEST,  // For model inference requests
    INFERENCE_RESULT,   // For inference results
    MODEL_UPDATE,       // For model weights updates
    CONTRACT_CALL,      // For smart contract calls
    UNDEFINED          // Undefined type
};

// ---------------------------
// 2. Transaction System
// ---------------------------

/**
 * Unspent Transaction Output (UTXO)
 * Similar to Bitcoin's model where each output can only be spent once.
 * Represents a specific balance owned by a specific address (public key).
 */
struct TransactionOutput {
    std::string txId;          // Parent transaction ID (hash of the parent transaction)
    int outputIndex;           // Output index within the parent transaction
    std::string owner;         // Owner address (public key in hex format)
    long long amount;          // Currency amount (changed from double to long long)

    // Default constructor for map usage (required for some map operations)
    TransactionOutput() : txId(""), outputIndex(-1), owner(""), amount(0) {}

    // Constructor to create a new UTXO
    TransactionOutput(std::string txId, int outputIndex, std::string owner, long long amount);

    // Creates a unique identifier for this UTXO
    std::string getId() const;

    // Serialization for hashing/signing
    std::string serializeForTransactionHash() const;
};

/**
 * Transaction Input - references a UTXO and provides a signature
 * proving ownership.
 * Represents a UTXO being spent in a new transaction.
 */
struct TransactionInput {
    std::string utxoId;       // ID of the UTXO being spent (TxId:OutputIndex)
    std::string signature;    // Digital signature of the sender (hex encoded)
    std::string publicKey;    // Public key of the sender (hex encoded)

    // Default constructor for map usage
    TransactionInput() : utxoId(""), signature(""), publicKey("") {}

    // Constructor to create a new TransactionInput
    TransactionInput(std::string utxoId, std::string signature, std::string publicKey);

    // Serialization for signing: what the sender signs to prove ownership of the UTXO.
    std::string serializeForSigning(const std::string& newTxId) const;

    // Serialization for transaction hash: unique properties of the input.
    std::string serializeForTransactionHash() const;
};

/**
 * A generic transaction that can handle various types of operations.
 * Modified to support different data types like inference requests and model updates,
 * not just financial transfers.
 */
class Transaction {
private:
    std::string txId;               // Unique hash of this transaction
    TransactionType type;           // Transaction type (NEW)
    std::int64_t timestamp;         // Transaction timestamp (milliseconds since epoch)
    std::string creatorPublicKey;   // Public key of transaction creator (NEW)
    std::string payload;            // Transaction-specific data in JSON format (NEW)
    std::vector<std::string> parentTxs;    // References to parent transactions in DAG structure
    std::string signature;          // Signature of transaction creator (NEW)

    // Internal function to calculate transaction ID (hash)
    void calculateId(); // Renamed from createId

public:
    // Constructor for building a new transaction with flexible payload
    Transaction(TransactionType txType,
        const std::string& creatorPubKey,
        const std::string& dataPayload,
        const std::vector<std::string>& parents = {});

    // Constructor for deserializing or recreating an already signed transaction
    Transaction(TransactionType txType,
        const std::string& creatorPubKey,
        const std::string& dataPayload,
        const std::vector<std::string>& parents,
        std::int64_t ts,
        const std::string& id,
        const std::string& sig);

    // Legacy constructor for backward compatibility (financial transactions)
    Transaction(std::vector<TransactionInput> ins,
        std::vector<TransactionOutput> outs,
        std::vector<std::string> parents = {});

    // Legacy constructor for deserializing financial transactions
    Transaction(std::vector<TransactionInput> ins,
        std::vector<TransactionOutput> outs,
        std::vector<std::string> parents,
        std::int64_t ts,
        std::string id);

    /**
     * @brief Signs the transaction with the provided private key
     * @param privateKey The private key to sign the transaction
     */
    void sign(const CryptoHelper::ECKeyPtr& privateKey);

    /**
     * @brief Verifies the transaction signature
     * @return True if signature is valid, false otherwise
     */
    bool verifySignature() const;

    /**
     * @brief Validates transaction integrity based on its type
     * For VALUE_TRANSFER: performs UTXO validation (double spending, signatures, etc.)
     * For other types: performs basic structural validation
     * @param utxoSet The current global UTXO set for validation (only used for VALUE_TRANSFER)
     * @return True if the transaction is valid, false otherwise
     * @throws TransactionError if validation fails due to integrity issues
     */
    bool validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const;

    // Getters
    const std::string& getId() const { return txId; }
    TransactionType getType() const { return type; }
    const std::string& getCreatorPublicKey() const { return creatorPublicKey; }
    const std::string& getPayload() const { return payload; }
    const std::vector<std::string>& getParents() const { return parentTxs; }
    const std::string& getSignature() const { return signature; }
    std::int64_t getTimestamp() const { return timestamp; }

    // Legacy getters for financial transactions (inputs and outputs stored in payload)
    std::vector<TransactionInput> getFinancialInputs() const;
    std::vector<TransactionOutput> getFinancialOutputs() const;

    /**
     * @brief Helper method to create a signed TransactionInput for financial transactions
     * This method is typically called by the client (wallet) or the node
     * before adding the transaction to the DAG/blockchain.
     * The signature covers the UTXO ID and the ID of the new transaction being created.
     * @param utxoId The ID of the UTXO being spent.
     * @param privateKey The private key of the UTXO owner.
     * @param currentTxId The ID of the transaction that this input belongs to.
     * @return A fully formed and signed TransactionInput.
     */
    TransactionInput createSignedInput(
        const std::string& utxoId,
        const CryptoHelper::ECKeyPtr& privateKey,
        const std::string& currentTxId
    );

    /**
     * @brief Serializes the transaction data to a JSON string
     * @return A JSON string representation of the transaction
     */
    std::string serialize() const;

    /**
     * @brief Deserializes a JSON string into a Transaction object
     * @param jsonString The JSON string representing a transaction
     * @return A shared_ptr to the deserialized Transaction object
     */
    static std::shared_ptr<Transaction> deserialize(const std::string& jsonString);

    /**
     * @brief Provides a human-readable string representation of the transaction
     * @return A string with transaction details
     */
    std::string toString() const;

    /**
     * @brief Converts TransactionType enum to string representation
     * @param type The transaction type to convert
     * @return String representation of the transaction type
     */
    static std::string transactionTypeToString(TransactionType type);

    /**
     * @brief Converts string to TransactionType enum
     * @param typeStr The string to convert
     * @return Corresponding TransactionType enum value
     */
    static TransactionType stringToTransactionType(const std::string& typeStr);
};

#endif // TRANSACTION_H
