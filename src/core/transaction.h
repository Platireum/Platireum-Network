#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <vector>
#include <unordered_map> // لاستخدامها لاحقاً في UTXO Set
#include <unordered_set> // لمنع تكرار صرف UTXO داخل المعاملة
#include <chrono>        // للحصول على الطابع الزمني (timestamp)
#include <sstream>       // للمساعدة في بناء السلاسل
#include <iomanip>       // للتنسيق

#include "crypto_helper.h" // نحتاج إلى دوال التشفير للهاش والتوقيع
#include <memory>        // For std::shared_ptr

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
 * Custom exception class for ledger errors (أو أخطاء دفتر الأستاذ العام)
 */
class LedgerError : public std::runtime_error {
public:
    explicit LedgerError(const std::string& msg) : std::runtime_error(msg) {}
};


// ---------------------------
// 2. Transaction System
// ---------------------------

/**
 * Unspent Transaction Output (UTXO)
 * Similar to Bitcoin's model where each output can only be spent once.
 * يمثل رصيداً معيناً يملكه عنوان معين (المفتاح العام).
 */
struct TransactionOutput {
    std::string txId;          // معرف المعاملة الأم (hash of the parent transaction)
    int outputIndex;           // مؤشر الخرج ضمن المعاملة الأم
    std::string owner;         // عنوان المالك (public key in hex format)
    long long amount;          // مقدار العملة (تم التغيير من double إلى long long)
    
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
 * يمثل UTXO يتم صرفه (إنفاقه) في معاملة جديدة.
 */
struct TransactionInput {
    std::string utxoId;       // معرف الـ UTXO الذي يتم صرفه (TxId:OutputIndex)
    std::string signature;    // التوقيع الرقمي للمرسل (hex encoded)
    std::string publicKey;    // المفتاح العام للمرسل (hex encoded)
    
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
 * A transaction moving value between addresses.
 * Can have multiple inputs (UTXOs being spent) and multiple outputs (new UTXOs created).
 * يمثل معاملة واحدة في الشبكة.
 */
class Transaction {
private:
    std::string txId;               // الهاش الفريد لهذه المعاملة
    std::vector<TransactionInput> inputs;   // قائمة بالمدخلات
    std::vector<TransactionOutput> outputs;  // قائمة بالمخرجات
    std::vector<std::string> parentTxs;    // مراجع إلى المعاملات الأب في هيكل DAG
    std::int64_t timestamp;                // الطابع الزمني للمعاملة (بالمللي ثانية منذ epoch)
    
    // دالة داخلية لحساب معرف المعاملة (hash)
    void createId();
    
public:
    // Constructor for building a new transaction (inputs initially without signatures)
    Transaction(std::vector<TransactionInput> ins,
                std::vector<TransactionOutput> outs,
                std::vector<std::string> parents = {});

    // Constructor for deserializing or recreating an already signed transaction
    Transaction(std::vector<TransactionInput> ins,
                std::vector<TransactionOutput> outs,
                std::vector<std::string> parents,
                std::int64_t ts,
                std::string id);
    
    /**
     * @brief Validates transaction integrity against a given UTXO set.
     * Performs checks for double spending, valid signatures, correct ownership,
     * and ensures input amount covers output amount.
     * @param utxoSet The current global UTXO set for validation.
     * @return True if the transaction is valid, false otherwise.
     * @throws TransactionError if validation fails due to integrity issues.
     */
    bool validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const;
    
    // Getters
    const std::string& getId() const { return txId; }
    const std::vector<TransactionInput>& getInputs() const { return inputs; }
    const std::vector<TransactionOutput>& getOutputs() const { return outputs; }
    const std::vector<std::string>& getParents() const { return parentTxs; }
    std::int64_t getTimestamp() const { return timestamp; }

    /**
     * @brief Helper method to create a signed TransactionInput.
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
     * @brief Serializes the transaction data to a JSON string.
     * @return A JSON string representation of the transaction.
     */
    std::string serialize() const;

    /**
     * @brief Deserializes a JSON string into a Transaction object.
     * @param jsonString The JSON string representing a transaction.
     * @return A shared_ptr to the deserialized Transaction object.
     */
    static std::shared_ptr<Transaction> deserialize(const std::string& jsonString);

    /**
     * @brief Provides a human-readable string representation of the transaction.
     * @return A string with transaction details.
     */
    std::string toString() const;
};

#endif // TRANSACTION_H