/*
 * Hybrid Blockchain-DAG System
 *
 * This combines the security of blockchain with the scalability of DAGs
 * Key features:
 * - Proof of Stake consensus
 * - Directed Acyclic Graph (DAG) for fast transactions
 * - Smart contract support (structural allowance, not implemented in detail)
 * - UTXO model like Bitcoin
 */

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <algorithm>
#include <random>
#include <sstream>
#include <chrono>
#include <functional>
#include <stdexcept>
#include <iostream>
#include <ctime>
#include <thread>
#include <atomic>
#include <mutex>
#include <optional>
#include <iomanip>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for cryptographic errors
 */
class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {
        // Get additional OpenSSL error info
        char errBuf[256];
        unsigned long err = ERR_get_error();
        if (err) {
            ERR_error_string_n(err, errBuf, sizeof(errBuf));
            std::cerr << "OpenSSL Error: " << errBuf << std::endl;
        }
    }
};

/**
 * Custom exception class for transaction errors
 */
class TransactionError : public std::runtime_error {
public:
    explicit TransactionError(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * Custom exception class for ledger errors
 */
class LedgerError : public std::runtime_error {
public:
    explicit LedgerError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 1. Crypto Utilities
// ---------------------------
/**
 * Handles all cryptographic operations
 * Uses OpenSSL under the hood but provides a simpler interface
 */
class CryptoHelper {
public:
    // Smart pointer that auto-frees EC keys
    using ECKeyPtr = std::shared_ptr<EC_KEY>;
    
    // Static flag for thread-safe OpenSSL initialization
    static std::once_flag cryptoInitFlag;

    // Helper to initialize OpenSSL once
    static void initializeOpenSSL() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    // Creates a new elliptic curve key pair
    static ECKeyPtr generateKeyPair() {
        std::call_once(cryptoInitFlag, initializeOpenSSL);
        
        ECKeyPtr key(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
        if (!key) {
            throw CryptoError("Failed to create key structure");
        }
        
        if (EC_KEY_generate_key(key.get()) != 1) {
            throw CryptoError("Failed to generate key pair");
        }
        
        // Set compression flag for more efficient storage
        EC_KEY_set_conv_form(key.get(), POINT_CONVERSION_COMPRESSED);
        
        return key;
    }

    // Extract public key as hex string
    static std::string getPublicKeyHex(const ECKeyPtr& key) {
        const EC_POINT* pubKey = EC_KEY_get0_public_key(key.get());
        if (!pubKey) {
            throw CryptoError("Failed to get public key");
        }
        
        const EC_GROUP* group = EC_KEY_get0_group(key.get());
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
        if (!ctx) {
            throw CryptoError("Failed to create BN context");
        }
        
        std::unique_ptr<char, decltype(&OPENSSL_free)> hexStr(
            EC_POINT_point2hex(group, pubKey, POINT_CONVERSION_COMPRESSED, ctx.get()),
            OPENSSL_free
        );
        
        if (!hexStr) {
            throw CryptoError("Failed to convert public key to hex");
        }
        
        return std::string(hexStr.get());
    }

    // Signs a message with private key
    static std::vector<unsigned char> signData(const ECKeyPtr& privateKey, const std::string& message) {
        std::call_once(cryptoInitFlag, initializeOpenSSL);
        // Hash the message first
        std::vector<unsigned char> msgHash = sha256Bytes(message);
        
        // Create signature
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
            ECDSA_do_sign(msgHash.data(), msgHash.size(), privateKey.get()),
            ECDSA_SIG_free
        );
        
        if (!sig) {
            throw CryptoError("Signing failed");
        }
        
        // Convert to DER format
        unsigned char* der = nullptr;
        int derLen = i2d_ECDSA_SIG(sig.get(), &der);
        
        if (derLen <= 0) {
            throw CryptoError("Failed to convert signature to DER format");
        }
        
        std::vector<unsigned char> signature(der, der + derLen);
        OPENSSL_free(der);
        
        return signature;
    }
    
    // Verify signature
    static bool verifySignature(const std::string& publicKeyHex, 
                               const std::vector<unsigned char>& signature, 
                               const std::string& message) {
        std::call_once(cryptoInitFlag, initializeOpenSSL);
        // Recreate EC_KEY from hex
        std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(
            EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free
        );
        if (!group) {
            throw CryptoError("Failed to create EC group");
        }
        
        std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(EC_KEY_new(), EC_KEY_free);
        if (!key) {
            throw CryptoError("Failed to create EC key");
        }
        
        if (EC_KEY_set_group(key.get(), group.get()) != 1) {
            throw CryptoError("Failed to set EC group");
        }
        
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
        if (!ctx) {
            throw CryptoError("Failed to create BN context");
        }
        
        std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(
            EC_POINT_new(group.get()), EC_POINT_free
        );
        
        if (!point || EC_POINT_hex2point(group.get(), publicKeyHex.c_str(), point.get(), ctx.get()) == nullptr) {
            throw CryptoError("Failed to decode public key");
        }
        
        if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
            throw CryptoError("Failed to set public key");
        }
        
        // Parse DER signature
        const unsigned char* derSig = signature.data();
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
            d2i_ECDSA_SIG(nullptr, &derSig, signature.size()),
            ECDSA_SIG_free
        );
        
        if (!sig) {
            throw CryptoError("Failed to parse signature");
        }
        
        // Verify
        std::vector<unsigned char> msgHash = sha256Bytes(message);
        int result = ECDSA_do_verify(msgHash.data(), msgHash.size(), sig.get(), key.get());
        
        if (result < 0) {
            throw CryptoError("Signature verification error");
        }
        
        return result == 1;
    }

    // Hashes data using SHA-256 and returns hex string
    static std::string sha256(const std::string& data) {
        std::vector<unsigned char> hash = sha256Bytes(data);
        
        // Convert to hex string
        std::stringstream ss;
        for (unsigned char byte : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        
        return ss.str();
    }
    
    // Hashes data using SHA-256 and returns raw bytes
    static std::vector<unsigned char> sha256Bytes(const std::string& data) {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdCtx(
            EVP_MD_CTX_new(), EVP_MD_CTX_free
        );
        
        if (!mdCtx) {
            throw CryptoError("Failed to create message digest context");
        }
        
        if (EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr) != 1) {
            throw CryptoError("Failed to initialize digest");
        }
        
        if (EVP_DigestUpdate(mdCtx.get(), data.c_str(), data.size()) != 1) {
            throw CryptoError("Failed to update digest");
        }
        
        unsigned int digestLen = 0;
        if (EVP_DigestFinal_ex(mdCtx.get(), hash.data(), &digestLen) != 1) {
            throw CryptoError("Failed to finalize digest");
        }
        
        hash.resize(digestLen);
        return hash;
    }
};

// Initialize the static once_flag
std::once_flag CryptoHelper::cryptoInitFlag;


// Helper for signatures
inline std::string bytesToHex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

inline std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// ---------------------------
// 2. Transaction System
// ---------------------------
/**
 * Unspent Transaction Output (UTXO)
 * Similar to Bitcoin's model where each output
 * can only be spent once
 */
struct TransactionOutput {
    std::string txId;       // Parent transaction ID (once part of a confirmed TX)
    int outputIndex;        // Which output in the transaction
    std::string owner;      // Owner's public address (public key in hex)
    double amount;          // How much cryptocurrency
    
    // Default constructor for map usage
    TransactionOutput() : txId(""), outputIndex(-1), owner(""), amount(0.0) {}

    TransactionOutput(std::string txId, int outputIndex, std::string owner, double amount)
        : txId(std::move(txId)), outputIndex(outputIndex), owner(std::move(owner)), amount(amount) {}

    std::string getId() const {
        if (txId.empty() || outputIndex == -1) {
            // This case should ideally not happen for a fully formed UTXO
            // For outputs within a new transaction *before* it's added to DAG,
            // their ID is not yet defined.
            return ""; 
        }
        return txId + ":" + std::to_string(outputIndex);
    }
    
    // Serialization for hashing/signing (for outputs *within* a new transaction, before they become UTXOs)
    // Only includes data that is stable at transaction creation time.
    std::string serializeForTransactionHash() const {
        std::stringstream ss;
        ss << owner << std::fixed << std::setprecision(8) << amount;
        return ss.str();
    }
};

/**
 * Transaction Input - references a UTXO
 * and provides a signature proving ownership
 */
struct TransactionInput {
    std::string utxoId;         // Reference to UTXO being spent
    std::string signature;      // Proof you own the UTXO (hex encoded)
    std::string publicKey;      // Spender's public key (hex encoded)
    
    // Default constructor for map usage
    TransactionInput() : utxoId(""), signature(""), publicKey("") {}

    TransactionInput(std::string utxoId, std::string signature, std::string publicKey)
        : utxoId(std::move(utxoId)), signature(std::move(signature)), publicKey(std::move(publicKey)) {}

    // Serialization for hashing/signing (only the part that needs to be signed)
    // This is the data that identifies the UTXO being spent and the new transaction.
    std::string serializeForSigning(const std::string& newTxId) const {
        return utxoId + newTxId;
    }

    // Serialization for transaction hash (only the part that makes the input unique)
    std::string serializeForTransactionHash() const {
        return utxoId + publicKey;
    }
};

/**
 * A transaction moving value between addresses
 * Can have multiple inputs and outputs
 */
class Transaction {
private:
    std::string txId;                       // Unique hash of this transaction
    std::vector<TransactionInput> inputs;
    std::vector<TransactionOutput> outputs;
    std::vector<std::string> parentTxs;    // For DAG structure
    std::int64_t timestamp;                 // Use standard int type
    
    // Creates the transaction ID by hashing all contents
    void createId() {
        std::stringstream data;
        data << timestamp;
        
        for (const auto& in : inputs) {
            // Inputs are signed with the *final* txId, but their unique properties
            // (utxoId, publicKey) are part of the transaction's own hash.
            data << in.serializeForTransactionHash(); 
        }
        
        for (const auto& out : outputs) {
            data << out.serializeForTransactionHash(); // Outputs hash only owner and amount
        }
        
        for (const auto& parent : parentTxs) {
            data << parent;
        }
        
        txId = CryptoHelper::sha256(data.str());
    }
    
public:
    // Constructor - builds a new transaction
    // Note: Inputs should NOT have signatures yet when constructing.
    // Signatures are added *after* txId is known.
    Transaction(std::vector<TransactionInput> ins,
                std::vector<TransactionOutput> outs,
                std::vector<std::string> parents = {})
        : inputs(std::move(ins)),
          outputs(std::move(outs)),
          parentTxs(std::move(parents)) 
    {
        timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        createId(); // Calculate initial hash
    }

    // Constructor for a transaction with already signed inputs
    // Used when deserializing or creating a transaction that's ready for validation
    Transaction(std::vector<TransactionInput> ins,
                std::vector<TransactionOutput> outs,
                std::vector<std::string> parents,
                std::int64_t ts,
                std::string id)
        : inputs(std::move(ins)),
          outputs(std::move(outs)),
          parentTxs(std::move(parents)),
          timestamp(ts),
          txId(std::move(id))
    {}
    
    // Validates transaction integrity
    bool validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const {
        // Recalculate ID to ensure it hasn't been tampered with
        std::string originalTxId = txId;
        const_cast<Transaction*>(this)->createId(); // Temporarily recalculate for verification
        if (originalTxId != txId) {
            // Restore original txId before throwing
            const_cast<Transaction*>(this)->txId = originalTxId;
            throw TransactionError("Transaction ID mismatch - integrity compromised!");
        }
        const_cast<Transaction*>(this)->txId = originalTxId; // Restore actual ID

        // Check inputs reference valid UTXOs
        double inputAmount = 0.0;
        std::unordered_set<std::string> spentUtxos; // To prevent double spending within the same TX
        for (const auto& input : inputs) {
            // Check for double spending within this transaction itself
            if (spentUtxos.count(input.utxoId) > 0) {
                return false; // Input UTXO spent multiple times in this TX
            }
            spentUtxos.insert(input.utxoId);

            // Check UTXO exists in the global UTXO set
            auto utxoIt = utxoSet.find(input.utxoId);
            if (utxoIt == utxoSet.end()) {
                return false; // UTXO not found or already spent
            }
            
            const auto& utxo = utxoIt->second;
            
            // Verify ownership with signature
            // Signature is created over the UTXO ID and the *new* transaction's ID
            std::string dataToVerify = input.serializeForSigning(this->txId);
            bool validSig = CryptoHelper::verifySignature(
                input.publicKey,
                hexToBytes(input.signature),
                dataToVerify
            );
            
            if (!validSig) {
                return false; // Invalid signature
            }
            
            // Verify public key matches UTXO owner
            if (utxo.owner != input.publicKey) {
                return false; // Input public key does not match UTXO owner
            }
            
            inputAmount += utxo.amount;
        }
        
        // Check output total doesn't exceed input total
        double outputAmount = 0.0;
        for (const auto& output : outputs) {
            if (output.amount <= 0) {
                return false;  // Negative or zero amounts not allowed
            }
            outputAmount += output.amount;
        }
        
        // Allow small numerical precision errors, but output cannot exceed input
        constexpr double EPSILON = 0.00000001; // Defined locally for precision checks
        return (outputAmount <= inputAmount + EPSILON);
    }
    
    // Getters
    const std::string& getId() const { return txId; }
    const std::vector<TransactionInput>& getInputs() const { return inputs; }
    const std::vector<TransactionOutput>& getOutputs() const { return outputs; }
    const std::vector<std::string>& getParents() const { return parentTxs; }
    std::int64_t getTimestamp() const { return timestamp; }

    // This method is for signing AFTER the transaction ID is known.
    // It should be called by the `HybridLedger` or client.
    TransactionInput createSignedInput(
        const std::string& utxoId,
        const CryptoHelper::ECKeyPtr& privateKey,
        const std::string& currentTxId) // Pass the actual ID of the transaction to sign for
    {
        // Get public key
        std::string publicKey = CryptoHelper::getPublicKeyHex(privateKey);
        
        // Sign the input using the current transaction's ID
        std::string dataToSign = utxoId + currentTxId;
        std::vector<unsigned char> signature = CryptoHelper::signData(privateKey, dataToSign);
        
        return {
            utxoId,
            bytesToHex(signature),
            publicKey
        };
    }
};

// ---------------------------
// 3. DAG Structure
// ---------------------------
/**
 * Manages the Directed Acyclic Graph of transactions
 * Handles tips selection and parent references
 */
class TransactionDAG {
private:
    std::unordered_map<std::string, Transaction> transactions;
    std::unordered_map<std::string, std::unordered_set<std::string>> children;
    std::unordered_set<std::string> tips; // Transactions with no children
    std::unordered_map<std::string, TransactionOutput> utxoSet; // Global UTXO set
    
    // Mutex for thread safety
    mutable std::mutex txMutex;
    
    // Update UTXO set after transaction validation and acceptance
    void updateUTXOSet(const Transaction& tx) {
        const std::string& txId = tx.getId();
        
        // Remove spent UTXOs
        for (const auto& input : tx.getInputs()) {
            utxoSet.erase(input.utxoId);
        }
        
        // Add new UTXOs from this transaction's outputs
        int outputIndex = 0;
        for (const auto& output : tx.getOutputs()) {
            // Note: The txId and outputIndex are assigned here, making them unique UTXOs
            TransactionOutput newUTXO{
                txId,
                outputIndex++,
                output.owner,
                output.amount
            };
            utxoSet[newUTXO.getId()] = std::move(newUTXO);
        }
    }
    
public:
    // Adds a transaction to the DAG
    bool addTransaction(const Transaction& tx) {
        std::lock_guard<std::mutex> lock(txMutex);
        
        const std::string& txId = tx.getId();
        
        // Check if already exists
        if (transactions.count(txId) > 0) {
            // This is not an error but indicates a duplicate attempt.
            // Depending on desired behavior, could log or return false.
            return false; 
        }
        
        // Validate parent references
        for (const auto& parent : tx.getParents()) {
            if (transactions.count(parent) == 0) {
                throw TransactionError("Parent transaction not found: " + parent);
            }
        }
        
        // Validate transaction integrity against current UTXO set
        if (!tx.validate(utxoSet)) { // Pass a copy to avoid modification during validation
            throw TransactionError("Transaction validation failed: " + txId);
        }
        
        // Update UTXO set (only if validation passes)
        updateUTXOSet(tx);
        
        // Add to storage
        transactions[txId] = tx;
        
        // Update child references
        for (const auto& parent : tx.getParents()) {
            children[parent].insert(txId);
            tips.erase(parent); // Parent is no longer a tip
        }
        
        // Add as new tip if it has no children yet
        // A transaction is a tip if no other transaction refers to it yet.
        if (children.count(txId) == 0) {
            tips.insert(txId);
        }
        
        return true;
    }
    
    // Gets current tip transactions (for new tx references)
    // Now truly selects top 'count' newest tips without random weighting
    std::vector<std::string> getTips(int count = 2) const {
        std::lock_guard<std::mutex> lock(txMutex);
        
        if (tips.empty()) {
            return {};
        }
        
        // Create a vector of tip IDs and their timestamps
        std::vector<std::pair<std::string, std::int64_t>> sortedTips;
        sortedTips.reserve(tips.size());
        for (const auto& tipId : tips) {
            // Check if the tip transaction actually exists before trying to access its timestamp.
            // This handles potential edge cases where a tip might be removed by a block without being fully processed.
            auto it = transactions.find(tipId);
            if (it != transactions.end()) {
                sortedTips.emplace_back(tipId, it->second.getTimestamp());
            }
        }
        
        // Sort by timestamp in descending order (newer first)
        std::sort(sortedTips.begin(), sortedTips.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        // Take top 'count' tips
        std::vector<std::string> result;
        result.reserve(std::min(count, static_cast<int>(sortedTips.size())));
        
        for (int i = 0; i < std::min(count, static_cast<int>(sortedTips.size())); ++i) {
            result.push_back(sortedTips[i].first);
        }
        
        return result;
    }
    
    // Get a transaction by ID
    std::optional<Transaction> getTransaction(const std::string& txId) const {
        std::lock_guard<std::mutex> lock(txMutex);
        
        auto it = transactions.find(txId);
        if (it != transactions.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    
    // Check if UTXO exists and is unspent
    bool isUTXOAvailable(const std::string& utxoId) const {
        std::lock_guard<std::mutex> lock(txMutex);
        return utxoSet.count(utxoId) > 0;
    }
    
    // Get available UTXOs for an address
    std::vector<TransactionOutput> getAddressUTXOs(const std::string& address) const {
        std::lock_guard<std::mutex> lock(txMutex);
        
        std::vector<TransactionOutput> result;
        for (const auto& pair : utxoSet) { // Iterate over pair to get both key and value
            const auto& utxo = pair.second;
            if (utxo.owner == address) {
                result.push_back(utxo);
            }
        }
        return result;
    }
    
    // Get total number of transactions
    size_t getTransactionCount() const {
        std::lock_guard<std::mutex> lock(txMutex);
        return transactions.size();
    }
    
    // Get UTXO set copy for external validation/state queries
    std::unordered_map<std::string, TransactionOutput> getUTXOSet() const {
        std::lock_guard<std::mutex> lock(txMutex);
        return utxoSet;
    }

    // A mechanism to "confirm" transactions from the DAG into the blockchain.
    // These transactions should ideally be removed from the DAG after being included in a block.
    // For simplicity, this example just uses getTips, but in a real system, it would be
    // a set of "approved" transactions ready for finality.
    // This is a placeholder for a more sophisticated DAG pruning/confirmation mechanism.
    void confirmTransactions(const std::vector<std::string>& confirmedTxIds) {
        std::lock_guard<std::mutex> lock(txMutex);
        for (const auto& txId : confirmedTxIds) {
            transactions.erase(txId); // Remove from DAG storage
            tips.erase(txId); // Ensure it's no longer a tip
            // Note: children map might still contain entries for these,
            // but since parent transactions are removed, they won't be referenced.
            // A more robust pruning mechanism would also clean up children map.
        }
    }
};

// ---------------------------
// 4. Blockchain Component
// ---------------------------
/**
 * Provides periodic finality to the DAG
 * by creating checkpoint blocks
 */
class FinalityChain {
public:
    struct Block {
        int blockNumber;
        std::string blockHash;
        std::string previousHash;
        std::vector<std::string> transactions; // List of transaction IDs from DAG
        std::string validator;
        std::int64_t timestamp;
        
        Block(int num, std::vector<std::string> txs, 
              std::string prevHash, std::string val)
            : blockNumber(num),
              transactions(std::move(txs)),
              previousHash(std::move(prevHash)),
              validator(std::move(val))
        {
            timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            
            blockHash = calculateHash();
        }
        
        std::string calculateHash() const {
            std::stringstream data;
            data << blockNumber << previousHash << validator << timestamp;
            for (const auto& tx : transactions) {
                data << tx;
            }
            return CryptoHelper::sha256(data.str());
        }
    };
    
private:
    std::vector<Block> blocks;
    mutable std::mutex chainMutex;
    
public:
    // Creates a new block from DAG transactions
    Block createBlock(const std::vector<std::string>& transactions,
                      const std::string& validator) 
    {
        std::lock_guard<std::mutex> lock(chainMutex);
        
        std::string prevHash = blocks.empty() ? "0" : blocks.back().blockHash;
        Block newBlock(blocks.size(), transactions, prevHash, validator);
        blocks.push_back(newBlock);
        
        return newBlock;
    }
    
    // Get the latest block
    std::optional<Block> getLatestBlock() const {
        std::lock_guard<std::mutex> lock(chainMutex);
        
        if (blocks.empty()) {
            return std::nullopt;
        }
        return blocks.back();
    }
    
    // Get block by height
    std::optional<Block> getBlockByHeight(int height) const {
        std::lock_guard<std::mutex> lock(chainMutex);
        
        if (height >= 0 && height < static_cast<int>(blocks.size())) {
            return blocks[height];
        }
        return std::nullopt;
    }
    
    // Get block by hash
    std::optional<Block> getBlockByHash(const std::string& hash) const {
        std::lock_guard<std::mutex> lock(chainMutex);
        
        for (const auto& block : blocks) {
            if (block.blockHash == hash) {
                return block;
            }
        }
        return std::nullopt;
    }
    
    // Get current chain height
    int getHeight() const {
        std::lock_guard<std::mutex> lock(chainMutex);
        return static_cast<int>(blocks.size());
    }
    
    // Get all blocks
    std::vector<Block> getAllBlocks() const {
        std::lock_guard<std::mutex> lock(chainMutex);
        return blocks;
    }
};

// ---------------------------
// 5. Validator System
// ---------------------------
/**
 * Manages validators and their stake
 */
class ValidatorManager {
private:
    struct ValidatorInfo {
        CryptoHelper::ECKeyPtr key; // Private key for signing blocks
        double stake;
        std::int64_t lastBlockTime; // Timestamp of the last block this validator created
    };
    
    std::unordered_map<std::string, ValidatorInfo> validators; // Key: validator address (public key hex)
    double totalStake = 0.0;
    std::mt19937 rng; // Random number generator for selection
    mutable std::mutex validatorMutex;
    
public:
    ValidatorManager() : rng(std::random_device{}()) {}
    
    // Adds a new validator node
    void addValidator(const std::string& address, CryptoHelper::ECKeyPtr key, double stake) {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        if (validators.count(address) > 0) {
            throw LedgerError("Validator already exists: " + address);
        }
        
        if (stake <= 0) {
            throw LedgerError("Stake amount must be positive.");
        }

        validators[address] = {
            std::move(key),
            stake,
            0 // Initialize last block time
        };
        
        totalStake += stake;
    }
    
    // Select a validator based on stake (PoS)
    // This uses a weighted random selection.
    std::string selectValidator() {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        if (validators.empty() || totalStake <= 0) {
            throw LedgerError("No active validators available for selection.");
        }
        
        std::vector<double> weights;
        std::vector<std::string> addresses;
        weights.reserve(validators.size());
        addresses.reserve(validators.size());

        for (const auto& [addr, info] : validators) {
            weights.push_back(info.stake); // Use raw stake as weight
            addresses.push_back(addr);
        }
        
        std::discrete_distribution<size_t> distribution(weights.begin(), weights.end());
        
        size_t selectedIdx = distribution(rng);
        return addresses[selectedIdx];
    }
    
    // Get validator's key for signing
    CryptoHelper::ECKeyPtr getValidatorKey(const std::string& address) const { // Changed to const
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        auto it = validators.find(address);
        if (it == validators.end()) {
            throw LedgerError("Validator not found: " + address);
        }
        
        return it->second.key; // Return copy of shared_ptr
    }
    
    // Update validator's last block time
    void updateBlockTime(const std::string& address, std::int64_t timestamp) {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        auto it = validators.find(address);
        if (it != validators.end()) {
            it->second.lastBlockTime = timestamp;
        } else {
            std::cerr << "Warning: Attempted to update block time for unknown validator: " << address << std::endl;
        }
    }
    
    // Get validator stake
    double getValidatorStake(const std::string& address) const {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        auto it = validators.find(address);
        if (it == validators.end()) {
            return 0.0;
        }
        
        return it->second.stake;
    }
    
    // Get all validators
    std::vector<std::string> getAllValidators() const {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        std::vector<std::string> result;
        result.reserve(validators.size());
        
        for (const auto& [addr, info] : validators) {
            result.push_back(addr);
        }
        
        return result;
    }
    
    // Get total stake
    double getTotalStake() const {
        std::lock_guard<std::mutex> lock(validatorMutex);
        return totalStake;
    }
};

// ---------------------------
// 6. Main System Class
// ---------------------------
/**
 * The complete hybrid system combining DAG and blockchain
 */
class HybridLedger {
private:
    TransactionDAG dag;
    FinalityChain chain;
    ValidatorManager validators;
    
    // Configuration
    static constexpr double MIN_STAKE = 1000.0; // Use constexpr for compile-time constant
    static constexpr int BLOCK_INTERVAL_SECONDS = 30; // seconds for block creation

    // For periodic block creation
    std::thread blockThread;
    std::atomic<bool> running{false};
    
    // Worker function for block creation thread
    void blockCreationWorker() {
        using namespace std::chrono;
        
        while (running) {
            auto nextBlockTime = steady_clock::now() + seconds(BLOCK_INTERVAL_SECONDS);
            
            try {
                // Select a validator
                std::string validatorAddress = validators.selectValidator();
                
                // Get the validator's private key for signing
                CryptoHelper::ECKeyPtr validatorKey = validators.getValidatorKey(validatorAddress);

                // Gather transactions for a new block (e.g., the newest tips)
                // In a real system, this would involve a more robust selection
                // of transactions ready for finalization.
                std::vector<std::string> transactionsToFinalize = dag.getTips(100); 
                
                if (!transactionsToFinalize.empty()) {
                    // Create and add the block to the finality chain
                    auto block = chain.createBlock(transactionsToFinalize, validatorAddress);
                    
                    // Update validator's last block time
                    validators.updateBlockTime(validatorAddress, block.timestamp);
                    
                    // After successful block creation, confirm these transactions in the DAG
                    // (i.e., remove them or mark them as finalized/pruned)
                    dag.confirmTransactions(transactionsToFinalize);
                    
                    std::cout << "Block #" << block.blockNumber << " created by " << validatorAddress 
                              << " with " << transactionsToFinalize.size() << " transactions. Hash: " 
                              << block.blockHash.substr(0, 8) << "..." << std::endl;
                } else {
                    std::cout << "No new transactions to include in block. Waiting..." << std::endl;
                }
            } catch (const LedgerError& e) {
                // Specific error for validator issues
                std::cerr << "Ledger Error in block creation: " << e.what() << std::endl;
            } catch (const std::exception& e) {
                // Catch all other exceptions
                std::cerr << "General Error in block creation: " << e.what() << std::endl;
            }
            
            // Sleep until next block time
            std::this_thread::sleep_until(nextBlockTime);
        }
    }

public:
    HybridLedger() {
        // Start with a genesis validator
        auto genesisKey = CryptoHelper::generateKeyPair();
        std::string genesisAddr = CryptoHelper::getPublicKeyHex(genesisKey);
        // Fund the genesis validator with some initial stake balance
        validators.addValidator(genesisAddr, genesisKey, MIN_STAKE * 10);
        
        // Create an initial UTXO for the genesis validator to start with funds
        // This is a special "minting" transaction or initial coin distribution.
        TransactionOutput genesisCoin("GENESIS_TX", 0, genesisAddr, 1000000.0); // 1,000,000 initial coins
        
        // Directly add this UTXO to the DAG's UTXO set (bypassing normal transaction validation for genesis)
        // In a real system, a genesis block would define initial UTXOs.
        // For simplicity, we directly modify the UTXO set here.
        // This must be done carefully to avoid breaking the UTXO set integrity.
        // For the purpose of this example, we'll simulate a genesis transaction.
        // This is a simplification; a true genesis block would be part of FinalityChain setup.
        
        // Simulating a "genesis transaction" to create initial UTXOs for the genesis validator
        // This won't go through the addTransaction path initially as it's the very first coin.
        std::vector<TransactionOutput> initialOutputs = {
            {"", 0, genesisAddr, 1000000.0} // Placeholder txId and index
        };
        Transaction genesisTx({}, initialOutputs, {}); // No inputs, no parents
        // Manually update the DAG's UTXO set for the genesis transaction
        // This is a hack for setup; typically, genesis transactions are hardcoded.
        // For a more robust system, consider a dedicated genesis block in FinalityChain
        // that initializes the UTXO set.
        
        // We need access to dag's internal utxoSet for this genesis coin.
        // For demonstration, let's just make the genesis coin part of the UTXO set directly.
        // In a proper system, a genesis block would have minted this.
        TransactionOutput actualGenesisUTXO("GENESIS_BLOCK_TX", 0, genesisAddr, 1000000.0);
        // Need to add this to the dag's utxoSet outside of addTransaction for initial state.
        // This highlights a need for better initialization or a "mint" transaction function.
        // For now, let's ensure the genesis validator has *some* coins to spend.
        // This part would ideally be handled by a specific "genesis" function in TransactionDAG.
        // Given current structure, we'll assume the genesis validator magically has funds.
        // In the example usage, we will directly add a "minting" transaction.


        // Start block creation thread
        running = true;
        blockThread = std::thread(&HybridLedger::blockCreationWorker, this);
    }

    ~HybridLedger() {
        running = false;
        if (blockThread.joinable()) {
            blockThread.join();
        }
        std::cout << "HybridLedger stopped." << std::endl;
    }

    // Add a new transaction to the DAG
    // This assumes the transaction has already been fully constructed and signed.
    bool addTransaction(const Transaction& tx) {
        try {
            return dag.addTransaction(tx);
        } catch (const TransactionError& e) {
            std::cerr << "Failed to add transaction: " << e.what() << std::endl;
            return false;
        } catch (const CryptoError& e) {
            std::cerr << "Crypto error during transaction addition: " << e.what() << std::endl;
            return false;
        }
    }

    // Create and add a new transaction
    // This method handles the logic of finding UTXOs and signing.
    std::string createTransaction(
        const CryptoHelper::ECKeyPtr& senderKey,
        const std::string& recipient,
        double amount)
    {
        std::string senderAddr = CryptoHelper::getPublicKeyHex(senderKey);
        std::vector<TransactionOutput> availableUtxos = dag.getAddressUTXOs(senderAddr);

        double inputTotal = 0.0;
        std::vector<TransactionOutput> inputsToUse;

        // Collect UTXOs until sufficient funds are gathered
        for (const auto& utxo : availableUtxos) {
            inputsToUse.push_back(utxo);
            inputTotal += utxo.amount;
            if (inputTotal >= amount) {
                break; // Found enough UTXOs
            }
        }

        if (inputTotal < amount) {
            throw TransactionError("Insufficient funds for transaction from " + senderAddr + ". Needed: " + std::to_string(amount) + ", available: " + std::to_string(inputTotal));
        }

        if (amount <= 0) {
            throw TransactionError("Transaction amount must be positive.");
        }

        // Create transaction outputs
        std::vector<TransactionOutput> outputs;
        
        // Payment to recipient
        // Note: txId and outputIndex are placeholders here; they are set when the TX becomes a UTXO
        outputs.push_back({"", 0, recipient, amount}); 

        // Change back to sender (if any)
        double change = inputTotal - amount;
        if (change > 0) {
            outputs.push_back({"", 1, senderAddr, change}); // Placeholder txId and index
        }

        // Get parent tips for the DAG
        std::vector<std::string> parentTips = dag.getTips(2);

        // Create the transaction object first to get its ID
        // Inputs here are not yet signed, they only contain utxoId and publicKey
        std::vector<TransactionInput> tempInputs; // Temporarily holds unsigned inputs for hash calculation
        for (const auto& utxo : inputsToUse) {
            tempInputs.push_back({utxo.getId(), "", senderAddr}); // Signature is empty
        }

        Transaction tx(tempInputs, outputs, parentTips);
        std::string newTxId = tx.getId(); // Get the ID of the newly created transaction

        // Now, sign the inputs using the calculated txId
        std::vector<TransactionInput> signedInputs;
        for (const auto& utxo : inputsToUse) {
            // Use the member function createSignedInput to access it
            signedInputs.push_back(tx.createSignedInput(utxo.getId(), senderKey, newTxId));
        }
        
        // Re-create the transaction with signed inputs. 
        // This is a common pattern: build a skeletal transaction, hash it, then sign inputs, then finalize.
        // For simplicity, we can pass the signed inputs to a new transaction constructor if needed,
        // or modify the existing one. For now, let's create a *new* valid transaction object.
        Transaction finalTx(signedInputs, outputs, parentTips, tx.getTimestamp(), newTxId);


        if (!dag.addTransaction(finalTx)) {
            throw TransactionError("Failed to add transaction to DAG after signing.");
        }

        return finalTx.getId();
    }

    // Register as a validator
    // Requires the validator to have sufficient funds (stake) that will be locked.
    // This example simplifies, by just "adding" stake without actual fund transfer.
    bool registerValidator(const CryptoHelper::ECKeyPtr& key, double stake) {
        if (stake < MIN_STAKE) {
            throw LedgerError("Stake amount too low. Minimum required: " + std::to_string(MIN_STAKE));
        }

        std::string address = CryptoHelper::getPublicKeyHex(key);
        // In a real system, this stake would need to be moved from the validator's UTXOs
        // into a "staking contract" or dedicated staking UTXO. This is a simplification.
        validators.addValidator(address, key, stake);
        std::cout << "Validator registered: " << address << " with stake: " << stake << std::endl;
        return true;
    }

    // Get transaction by ID
    std::optional<Transaction> getTransaction(const std::string& txId) const {
        return dag.getTransaction(txId);
    }

    // Get UTXOs for an address
    std::vector<TransactionOutput> getAddressUTXOs(const std::string& address) const {
        return dag.getAddressUTXOs(address);
    }

    // Get current DAG size (number of unconfirmed transactions)
    size_t getDAGSize() const {
        return dag.getTransactionCount();
    }

    // Get blockchain height
    int getBlockchainHeight() const {
        return chain.getHeight();
    }

    // Get validator information
    double getValidatorStake(const std::string& address) const {
        return validators.getValidatorStake(address);
    }

    // Get latest block
    std::optional<FinalityChain::Block> getLatestBlock() const {
        return chain.getLatestBlock();
    }

    // Get all validators
    std::vector<std::string> getAllValidators() const {
        return validators.getAllValidators();
    }
};

// --- Example Usage (main function) ---
int main() {
    std::cout << "Starting Hybrid Blockchain-DAG System Simulation..." << std::endl;

    try {
        HybridLedger ledger; // Initializes genesis validator and starts block thread

        // --- Setup Users and Initial Funds ---
        // User 1 (Sender)
        auto user1_key = CryptoHelper::generateKeyPair();
        std::string user1_address = CryptoHelper::getPublicKeyHex(user1_key);
        std::cout << "\nUser 1 Address: " << user1_address << std::endl;

        // User 2 (Recipient)
        auto user2_key = CryptoHelper::generateKeyPair();
        std::string user2_address = CryptoHelper::getPublicKeyHex(user2_key);
        std::cout << "User 2 Address: " << user2_address << std::endl;

        // A "minting" transaction or initial distribution to User 1
        // In a real system, this comes from a genesis block or a specific minting function.
        // Here, we simulate a initial fund to User 1 as a UTXO.
        // We'll directly create a UTXO for User1. This bypasses the normal transaction flow,
        // which would typically be part of a genesis block or a specific "mint" operation.
        // For demonstration purposes, we will treat it as a special "initialization" UTXO.
        // A more robust implementation would involve a proper genesis block/transaction.
        // This is a simplification to allow transactions to be created immediately.
        // We will assume that `dag.addTransaction` can handle a special "minting" tx with no inputs.
        
        // Simulating a "mint" transaction to give user1 initial funds
        std::vector<TransactionOutput> mintOutputs = {
            {"", 0, user1_address, 5000.0} // Funds for User1
        };
        Transaction mintTx({}, mintOutputs, {}); // No inputs, no parents (a genesis-like transaction)
        std::cout << "Simulating minting 5000.0 coins to User 1: " << mintTx.getId() << std::endl;
        ledger.addTransaction(mintTx); // Add this special minting transaction

        // Wait a moment for the system to process initial state
        std::this_thread::sleep_for(std::chrono::seconds(1));

        std::cout << "\n--- Current UTXOs for User 1 after minting ---" << std::endl;
        std::vector<TransactionOutput> user1_utxos_initial = ledger.getAddressUTXOs(user1_address);
        for (const auto& utxo : user1_utxos_initial) {
            std::cout << "  UTXO ID: " << utxo.getId() << ", Amount: " << utxo.amount << ", Owner: " << utxo.owner.substr(0, 8) << "..." << std::endl;
        }
        if (user1_utxos_initial.empty()) {
            std::cout << "User 1 has no UTXOs after initial minting." << std::endl;
        }

        // --- Create a Transaction ---
        std::cout << "\n--- User 1 sending 100.0 to User 2 ---" << std::endl;
        try {
            std::string tx1_id = ledger.createTransaction(user1_key, user2_address, 100.0);
            std::cout << "Transaction 1 created: " << tx1_id << std::endl;
        } catch (const TransactionError& e) {
            std::cerr << "Failed to create transaction: " << e.what() << std::endl;
        }

        // Add more transactions (stress test DAG)
        std::cout << "\n--- Creating multiple small transactions ---" << std::endl;
        for (int i = 0; i < 5; ++i) {
            try {
                // User 1 sending small amounts to User 2 to generate more DAG activity
                std::string small_tx_id = ledger.createTransaction(user1_key, user2_address, 1.0);
                std::cout << "Small Transaction " << (i + 1) << " created: " << small_tx_id << std::endl;
            } catch (const TransactionError& e) {
                std::cerr << "Failed to create small transaction " << (i + 1) << ": " << e.what() << std::endl;
            }
        }


        // --- Check DAG and Blockchain state ---
        std::cout << "\n--- System State ---" << std::endl;
        std::cout << "DAG Size: " << ledger.getDAGSize() << " transactions" << std::endl;
        std::cout << "Blockchain Height: " << ledger.getBlockchainHeight() << " blocks" << std::endl;

        // Give some time for blocks to be created
        std::cout << "\nWaiting for blocks to be created (approx " << HybridLedger::BLOCK_INTERVAL_SECONDS * 2 << " seconds for 2 blocks)..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(HybridLedger::BLOCK_INTERVAL_SECONDS * 2));

        std::cout << "\n--- System State after some time ---" << std::endl;
        std::cout << "DAG Size: " << ledger.getDAGSize() << " transactions (should decrease as TXs are included in blocks)" << std::endl;
        std::cout << "Blockchain Height: " << ledger.getBlockchainHeight() << " blocks" << std::endl;

        std::cout << "\n--- Latest Block Info ---" << std::endl;
        auto latestBlock = ledger.getLatestBlock();
        if (latestBlock) {
            std::cout << "Block Number: " << latestBlock->blockNumber << std::endl;
            std::cout << "Block Hash: " << latestBlock->blockHash << std::endl;
            std::cout << "Validator: " << latestBlock->validator.substr(0, 8) << "..." << std::endl;
            std::cout << "Transactions in block: " << latestBlock->transactions.size() << std::endl;
        } else {
            std::cout << "No blocks in the chain yet." << std::endl;
        }

        std::cout << "\n--- Current UTXOs for User 1 ---" << std::endl;
        std::vector<TransactionOutput> user1_utxos_final = ledger.getAddressUTXOs(user1_address);
        for (const auto& utxo : user1_utxos_final) {
            std::cout << "  UTXO ID: " << utxo.getId() << ", Amount: " << utxo.amount << ", Owner: " << utxo.owner.substr(0, 8) << "..." << std::endl;
        }
        if (user1_utxos_final.empty()) {
            std::cout << "User 1 has no remaining UTXOs (or they are still being processed/confirmed)." << std::endl;
        }

        std::cout << "\n--- Current UTXOs for User 2 ---" << std::endl;
        std::vector<TransactionOutput> user2_utxos = ledger.getAddressUTXOs(user2_address);
        for (const auto& utxo : user2_utxos) {
            std::cout << "  UTXO ID: " << utxo.getId() << ", Amount: " << utxo.amount << ", Owner: " << utxo.owner.substr(0, 8) << "..." << std::endl;
        }
        if (user2_utxos.empty()) {
            std::cout << "User 2 has no UTXOs yet." << std::endl;
        }


        // --- Register another validator ---
        std::cout << "\n--- Registering another validator ---" << std::endl;
        auto validator2_key = CryptoHelper::generateKeyPair();
        std::string validator2_address = CryptoHelper::getPublicKeyHex(validator2_key);
        try {
            // Need to get some UTXOs for validator2 to stake (simulating fund transfer)
            // For simplicity, we'll assume validator2 magically has some initial funds here too.
            // In a real system, they would receive funds via a transaction from user1 or genesis.
            
            // Simulating a "mint" for validator2 to get stakeable funds
            std::vector<TransactionOutput> validator2MintOutputs = {
                {"", 0, validator2_address, 2000.0}
            };
            Transaction validator2MintTx({}, validator2MintOutputs, {});
            ledger.addTransaction(validator2MintTx);
            std::cout << "Simulating minting 2000.0 coins for Validator 2: " << validator2MintTx.getId() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Short delay

            ledger.registerValidator(validator2_key, 1500.0);
            std::cout << "Validator 2 Address: " << validator2_address << std::endl;
        } catch (const LedgerError& e) {
            std::cerr << "Failed to register validator 2: " << e.what() << std::endl;
        }

        std::cout << "\n--- Final System State ---" << std::endl;
        std::cout << "DAG Size: " << ledger.getDAGSize() << " transactions" << std::endl;
        std::cout << "Blockchain Height: " << ledger.getBlockchainHeight() << " blocks" << std::endl;
        
        std::cout << "\n--- All Validators ---" << std::endl;
        for(const auto& val_addr : ledger.getAllValidators()) {
            std::cout << "Validator: " << val_addr.substr(0, 8) << "..., Stake: " << ledger.getValidatorStake(val_addr) << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(HybridLedger::BLOCK_INTERVAL_SECONDS + 5)); // Allow some more blocks with new validator

    } catch (const std::exception& e) {
        std::cerr << "An unhandled exception occurred in main: " << e.what() << std::endl;
    }

    std::cout << "\nSimulation Finished." << std::endl;
    return 0;
}
