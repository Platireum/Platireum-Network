/*
 * Hybrid Blockchain-DAG System
 * 
 * This combines the security of blockchain with the scalability of DAGs
 * Key features:
 * - Proof of Stake consensus
 * - Directed Acyclic Graph (DAG) for fast transactions
 * - Smart contract support
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
    
    // Creates a new elliptic curve key pair
    static ECKeyPtr generateKeyPair() {
        // Initialize OpenSSL
        static bool initialized = false;
        if (!initialized) {
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
            initialized = true;
        }
        
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
        // Recreate EC_KEY from hex
        const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group) {
            throw CryptoError("Failed to create EC group");
        }
        
        std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(EC_KEY_new(), EC_KEY_free);
        if (!key) {
            EC_GROUP_free(const_cast<EC_GROUP*>(group));
            throw CryptoError("Failed to create EC key");
        }
        
        if (EC_KEY_set_group(key.get(), group) != 1) {
            EC_GROUP_free(const_cast<EC_GROUP*>(group));
            throw CryptoError("Failed to set EC group");
        }
        
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
        if (!ctx) {
            EC_GROUP_free(const_cast<EC_GROUP*>(group));
            throw CryptoError("Failed to create BN context");
        }
        
        std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(
            EC_POINT_new(group), EC_POINT_free
        );
        
        if (!point || EC_POINT_hex2point(group, publicKeyHex.c_str(), point.get(), ctx.get()) == nullptr) {
            EC_GROUP_free(const_cast<EC_GROUP*>(group));
            throw CryptoError("Failed to decode public key");
        }
        
        if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
            EC_GROUP_free(const_cast<EC_GROUP*>(group));
            throw CryptoError("Failed to set public key");
        }
        
        // Parse DER signature
        const unsigned char* derSig = signature.data();
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
            d2i_ECDSA_SIG(nullptr, &derSig, signature.size()),
            ECDSA_SIG_free
        );
        
        if (!sig) {
            EC_GROUP_free(const_cast<EC_GROUP*>(group));
            throw CryptoError("Failed to parse signature");
        }
        
        // Verify
        std::vector<unsigned char> msgHash = sha256Bytes(message);
        int result = ECDSA_do_verify(msgHash.data(), msgHash.size(), sig.get(), key.get());
        
        EC_GROUP_free(const_cast<EC_GROUP*>(group));
        
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
    std::string txId;      // Parent transaction ID
    int outputIndex;       // Which output in the transaction
    std::string owner;     // Owner's public address (public key in hex)
    double amount;         // How much cryptocurrency
    
    std::string getId() const {
        return txId + ":" + std::to_string(outputIndex);
    }
    
    // Serialization for hashing/signing
    std::string serialize() const {
        std::stringstream ss;
        ss << txId << outputIndex << owner << std::fixed << std::setprecision(8) << amount;
        return ss.str();
    }
};

/**
 * Transaction Input - references a UTXO
 * and provides a signature proving ownership
 */
struct TransactionInput {
    std::string utxoId;          // Reference to UTXO being spent
    std::string signature;       // Proof you own the UTXO (hex encoded)
    std::string publicKey;       // Spender's public key (hex encoded)
    
    // Serialization for hashing/signing
    std::string serialize() const {
        return utxoId + publicKey;
    }
};

/**
 * A transaction moving value between addresses
 * Can have multiple inputs and outputs
 */
class Transaction {
private:
    std::string txId;                     // Unique hash of this transaction
    std::vector<TransactionInput> inputs;
    std::vector<TransactionOutput> outputs;
    std::vector<std::string> parentTxs;   // For DAG structure
    std::int64_t timestamp;               // Use standard int type
    
    // Creates the transaction ID by hashing all contents
    void createId() {
        std::stringstream data;
        data << timestamp;
        
        for (const auto& in : inputs) {
            data << in.serialize();
        }
        
        for (const auto& out : outputs) {
            data << out.serialize();
        }
        
        for (const auto& parent : parentTxs) {
            data << parent;
        }
        
        txId = CryptoHelper::sha256(data.str());
    }
    
public:
    // Constructor - builds a new transaction
    Transaction(std::vector<TransactionInput> ins,
               std::vector<TransactionOutput> outs,
               std::vector<std::string> parents = {})
        : inputs(std::move(ins)),
          outputs(std::move(outs)),
          parentTxs(std::move(parents)) 
    {
        // Use high-precision timestamp
        timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        createId();
    }
    
    // Validates transaction integrity
    bool validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const {
        // Check inputs reference valid UTXOs
        double inputAmount = 0.0;
        for (const auto& input : inputs) {
            // Check UTXO exists
            auto utxoIt = utxoSet.find(input.utxoId);
            if (utxoIt == utxoSet.end()) {
                return false;
            }
            
            const auto& utxo = utxoIt->second;
            
            // Verify ownership with signature
            std::string dataToVerify = input.utxoId + txId;
            bool validSig = CryptoHelper::verifySignature(
                input.publicKey,
                hexToBytes(input.signature),
                dataToVerify
            );
            
            if (!validSig) {
                return false;
            }
            
            // Verify public key matches UTXO owner
            if (utxo.owner != input.publicKey) {
                return false;
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
        constexpr double EPSILON = 0.00000001;
        return (outputAmount <= inputAmount + EPSILON);
    }
    
    // Creates signed inputs using a private key
    static TransactionInput createSignedInput(
        const std::string& utxoId,
        const CryptoHelper::ECKeyPtr& privateKey,
        const std::string& txId)
    {
        // Get public key
        std::string publicKey = CryptoHelper::getPublicKeyHex(privateKey);
        
        // Sign the input
        std::string dataToSign = utxoId + txId;
        std::vector<unsigned char> signature = CryptoHelper::signData(privateKey, dataToSign);
        
        return {
            utxoId,
            bytesToHex(signature),
            publicKey
        };
    }
    
    // Getters
    const std::string& getId() const { return txId; }
    const std::vector<TransactionInput>& getInputs() const { return inputs; }
    const std::vector<TransactionOutput>& getOutputs() const { return outputs; }
    const std::vector<std::string>& getParents() const { return parentTxs; }
    std::int64_t getTimestamp() const { return timestamp; }
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
    std::unordered_map<std::string, TransactionOutput> utxoSet; // For validation
    
    // Mutex for thread safety
    mutable std::mutex txMutex;
    
    // Update UTXO set after transaction validation
    void updateUTXOSet(const Transaction& tx) {
        const std::string& txId = tx.getId();
        
        // Remove spent UTXOs
        for (const auto& input : tx.getInputs()) {
            utxoSet.erase(input.utxoId);
        }
        
        // Add new UTXOs
        int outputIndex = 0;
        for (const auto& output : tx.getOutputs()) {
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
            return false;
        }
        
        // Validate parent references
        for (const auto& parent : tx.getParents()) {
            if (transactions.count(parent) == 0) {
                throw TransactionError("Parent transaction not found: " + parent);
            }
        }
        
        // Validate transaction integrity against UTXO set
        if (!tx.validate(utxoSet)) {
            throw TransactionError("Transaction validation failed: " + txId);
        }
        
        // Update UTXO set
        updateUTXOSet(tx);
        
        // Add to storage
        transactions[txId] = tx;
        
        // Update child references
        for (const auto& parent : tx.getParents()) {
            children[parent].insert(txId);
            tips.erase(parent); // Parent is no longer a tip
        }
        
        // Add as new tip if it has no children yet
        if (children.count(txId) == 0) {
            tips.insert(txId);
        }
        
        return true;
    }
    
    // Gets current tip transactions (for new tx references)
    std::vector<std::string> getTips(int count = 2) const {
        std::lock_guard<std::mutex> lock(txMutex);
        
        if (tips.empty()) {
            return {};
        }
        
        // Random but weighted selection (prefer newer transactions)
        std::vector<std::pair<std::string, std::int64_t>> weightedTips;
        for (const auto& tipId : tips) {
            const auto& tx = transactions.at(tipId);
            weightedTips.emplace_back(tipId, tx.getTimestamp());
        }
        
        // Sort by timestamp (newer first)
        std::sort(weightedTips.begin(), weightedTips.end(), 
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        // Take top 'count' tips, or all if fewer available
        std::vector<std::string> result;
        result.reserve(std::min(count, static_cast<int>(weightedTips.size())));
        
        for (size_t i = 0; i < std::min(static_cast<size_t>(count), weightedTips.size()); ++i) {
            result.push_back(weightedTips[i].first);
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
        for (const auto& [id, utxo] : utxoSet) {
            if (utxo.owner == address) {
                result.push_back(utxo);
            }
        }
        return result;
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
        std::vector<std::string> transactions;
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
        CryptoHelper::ECKeyPtr key;
        double stake;
        std::int64_t lastBlockTime;
    };
    
    std::unordered_map<std::string, ValidatorInfo> validators;
    double totalStake = 0.0;
    std::mt19937 rng;
    mutable std::mutex validatorMutex;
    
public:
    ValidatorManager() : rng(std::random_device{}()) {}
    
    // Adds a new validator node
    void addValidator(const std::string& address, CryptoHelper::ECKeyPtr key, double stake) {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        if (validators.count(address) > 0) {
            throw LedgerError("Validator already exists: " + address);
        }
        
        validators[address] = {
            std::move(key),
            stake,
            0
        };
        
        totalStake += stake;
    }
    
    // Select a validator based on stake (PoS)
    std::string selectValidator() {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        if (validators.empty()) {
            throw LedgerError("No validators available");
        }
        
        // Weighted random selection based on stake
        std::vector<std::pair<std::string, double>> weightedValidators;
        weightedValidators.reserve(validators.size());
        
        for (const auto& [addr, info] : validators) {
            weightedValidators.emplace_back(addr, info.stake / totalStake);
        }
        
        std::discrete_distribution<size_t> distribution(
            weightedValidators.begin(),
            weightedValidators.end(),
            [](const auto& pair) { return pair.second; }
        );
        
        size_t selectedIdx = distribution(rng);
        return weightedValidators[selectedIdx].first;
    }
    
    // Get validator's key for signing
    CryptoHelper::ECKeyPtr getValidatorKey(const std::string& address) {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        auto it = validators.find(address);
        if (it == validators.end()) {
            throw LedgerError("Validator not found: " + address);
        }
        
        return it->second.key;
    }
    
    // Update validator's last block time
    void updateBlockTime(const std::string& address, std::int64_t timestamp) {
        std::lock_guard<std::mutex> lock(validatorMutex);
        
        auto it = validators.find(address);
        if (it != validators.end()) {
            it->second.lastBlockTime = timestamp;
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
    const double MIN_STAKE = 1000.0;
    const int BLOCK_INTERVAL = 30; // seconds
    
    // For periodic block creation
    std::thread blockThread;
    std::atomic<bool> running{false};
    
    // Worker function for block creation thread
    void blockCreationWorker() {
        using namespace std::chrono;
        
        while (running) {
            auto nextBlockTime = steady_clock::now() + seconds(BLOCK_INTERVAL);
            
            try {
                // Gather transactions for a new block
                auto tips = dag.getTips(100);  // Get up to 100 tips
                
                if (!tips.empty()) {
                    // Select validator based on stake
                    std::string validator = validators.selectValidator();
                    
                    // Create and sign the block
                    auto block = chain.createBlock(tips, validator);
                    
                    // Update validator's last block time
                    validators.updateBlockTime(validator,
