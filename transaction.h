#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <vector>
#include <unordered_map> // لاستخدامها لاحقاً في UTXO Set
#include <unordered_set> // لمنع تكرار صرف UTXO داخل المعاملة
#include <chrono>        // للحصول على الطابع الزمني (timestamp)
#include <sstream>       // للمساعدة في بناء السلاسل
#include <iomanip>       // للتنسيق العشري للعملات

#include "crypto_helper.h" // نحتاج إلى دوال التشفير للهاش والتوقيع

// ---------------------------
// 0. Error Handling (يمكن تعريفها هنا أيضاً أو في ملف منفصل للأخطاء العامة)
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
    std::string txId;        // معرف المعاملة الأم (hash of the parent transaction)
    int outputIndex;         // مؤشر الخرج ضمن المعاملة الأم
    std::string owner;       // عنوان المالك (public key in hex format)
    double amount;           // مقدار العملة (يُفضل استخدام أعداد صحيحة كبيرة بدلاً من double في الإنتاج)
    
    // Default constructor for map usage (required for some map operations)
    TransactionOutput() : txId(""), outputIndex(-1), owner(""), amount(0.0) {}

    // Constructor to create a new UTXO
    TransactionOutput(std::string txId, int outputIndex, std::string owner, double amount);

    // Creates a unique identifier for this UTXO
    std::string getId() const;
    
    // Serialization for hashing/signing (for outputs *within* a new transaction, before they become UTXOs)
    // Only includes data that is stable at transaction creation time (owner and amount).
    std::string serializeForTransactionHash() const;
};

/**
 * Transaction Input - references a UTXO and provides a signature
 * proving ownership.
 * يمثل UTXO يتم صرفه (إنفاقه) في معاملة جديدة.
 */
struct TransactionInput {
    std::string utxoId;      // معرف الـ UTXO الذي يتم صرفه (TxId:OutputIndex)
    std::string signature;   // التوقيع الرقمي للمرسل (hex encoded)
    std::string publicKey;   // المفتاح العام للمرسل (hex encoded)
    
    // Default constructor for map usage
    TransactionInput() : utxoId(""), signature(""), publicKey("") {}

    // Constructor to create a new TransactionInput
    TransactionInput(std::string utxoId, std::string signature, std::string publicKey);

    // Serialization for signing: what the sender signs to prove ownership of the UTXO.
    // It should include the UTXO ID and the ID of the new transaction it's part of.
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
    std::string txId;                      // الهاش الفريد لهذه المعاملة
    std::vector<TransactionInput> inputs;  // قائمة بالمدخلات (UTXOs التي يتم صرفها)
    std::vector<TransactionOutput> outputs; // قائمة بالمخرجات (UTXOs الجديدة التي يتم إنشاؤها)
    std::vector<std::string> parentTxs;    // مراجع إلى المعاملات الأب في هيكل DAG
    std::int64_t timestamp;                // الطابع الزمني للمعاملة (بالمللي ثانية منذ epoch)
    
    // دالة داخلية لحساب معرف المعاملة (hash)
    void createId();
    
public:
    // Constructor for building a new transaction (inputs initially without signatures)
    // يُستخدم هذا الكونستراكتور عندما يتم إنشاء المعاملة لأول مرة.
    // يتم التوقيع على المدخلات لاحقاً بعد معرفة txId.
    Transaction(std::vector<TransactionInput> ins,
                std::vector<TransactionOutput> outs,
                std::vector<std::string> parents = {});

    // Constructor for deserializing or recreating an already signed transaction
    // يُستخدم هذا الكونستراكتور عند تحميل معاملة من التخزين أو الشبكة.
    Transaction(std::vector<TransactionInput> ins,
                std::vector<TransactionOutput> outs,
                std::vector<std::string> parents,
                std::int64_t ts,
                std::string id);
    
    /**
     * Validates transaction integrity against a given UTXO set.
     * Performs checks for double spending, valid signatures, correct ownership,
     * and ensures input amount covers output amount.
     * @param utxoSet The current global UTXO set for validation.
     * @return True if the transaction is valid, false otherwise.
     * @throws TransactionError if validation fails due to integrity issues.
     */
    bool validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const;
    
    // Getters (دوال لجلب البيانات)
    const std::string& getId() const { return txId; }
    const std::vector<TransactionInput>& getInputs() const { return inputs; }
    const std::vector<TransactionOutput>& getOutputs() const { return outputs; }
    const std::vector<std::string>& getParents() const { return parentTxs; }
    std::int64_t getTimestamp() const { return timestamp; }

    /**
     * Helper method to create a signed TransactionInput.
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
};

#endif // TRANSACTION_H
