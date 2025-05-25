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
    
    // Get total number of transactions
    size_t getTransactionCount() const {
        std::lock_guard<std::mutex> lock(txMutex);
        return transactions.size();
    }
    
    // Get UTXO set copy for external validation
    std::unordered_map<std::string, TransactionOutput> getUTXOSet() const {
        std::lock_guard<std::mutex> lock(txMutex);
        return utxoSet;
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
                    validators.updateBlockTime(validator, block.timestamp);
                    
                                       std::cout << "Block #" << block.blockNumber << " created by " << validator 
                              << " with " << tips.size() << " transactions" << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error in block creation: " << e.what() << std::endl;
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
        validators.addValidator(genesisAddr, genesisKey, MIN_STAKE * 10);
        
        // Start block creation thread
        running = true;
        blockThread = std::thread(&HybridLedger::blockCreationWorker, this);
    }

    ~HybridLedger() {
        running = false;
        if (blockThread.joinable()) {
            blockThread.join();
        }
    }

    // Add a new transaction to the DAG
    bool addTransaction(const Transaction& tx) {
        return dag.addTransaction(tx);
    }

    // Create and add a new transaction
    std::string createTransaction(
        const CryptoHelper::ECKeyPtr& senderKey,
        const std::string& recipient,
        double amount,
        const std::vector<TransactionOutput>& inputs)
    {
        // Validate inputs
        double inputTotal = 0.0;
        for (const auto& input : inputs) {
            if (!dag.isUTXOAvailable(input.getId())) {
                throw TransactionError("Input UTXO not available: " + input.getId());
            }
            inputTotal += input.amount;
        }

        if (amount <= 0 || inputTotal < amount) {
            throw TransactionError("Invalid transaction amount");
        }

        // Create transaction outputs
        std::vector<TransactionOutput> outputs;
        
        // Payment to recipient
        outputs.push_back({
            "", // Will be set by Transaction constructor
            0,
            recipient,
            amount
        });

        // Change back to sender (if any)
        double change = inputTotal - amount;
        if (change > 0) {
            std::string senderAddr = CryptoHelper::getPublicKeyHex(senderKey);
            outputs.push_back({
                "", // Will be set by Transaction constructor
                1,
                senderAddr,
                change
            });
        }

        // Create signed inputs
        std::vector<TransactionInput> signedInputs;
        std::vector<std::string> parentTips = dag.getTips(2); // Reference 2 parent tips

        for (const auto& input : inputs) {
            signedInputs.push_back(Transaction::createSignedInput(
                input.getId(),
                senderKey,
                "" // Will be set by Transaction constructor
            ));
        }

        // Create and add transaction
        Transaction tx(signedInputs, outputs, parentTips);
        if (!dag.addTransaction(tx)) {
            throw TransactionError("Failed to add transaction to DAG");
        }

        return tx.getId();
    }

    // Register as a validator
    bool registerValidator(const CryptoHelper::ECKeyPtr& key, double stake) {
        if (stake < MIN_STAKE) {
            throw LedgerError("Stake amount too low");
        }

        std::string address = CryptoHelper::getPublicKeyHex(key);
        validators.addValidator(address, key, stake);
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

    // Get current DAG size
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

    // Get total staked amount
    double getTotalStake() const {
        return validators.getTotalStake();
    }

    // Get latest block
    std::optional<FinalityChain::Block> getLatestBlock() const {
        return chain.getLatestBlock();
    }

    // Get all blocks
    std::vector<FinalityChain::Block> getAllBlocks() const {
        return chain.getAllBlocks();
    }
};

// ---------------------------
// 7. Example Usage
// ---------------------------

int main() {
    try {
        // Initialize the hybrid ledger
        HybridLedger ledger;

        // Create some user key pairs
        auto aliceKey = CryptoHelper::generateKeyPair();
        auto bobKey = CryptoHelper::generateKeyPair();
        
        std::string aliceAddr = CryptoHelper::getPublicKeyHex(aliceKey);
        std::string bobAddr = CryptoHelper::getPublicKeyHex(bobKey);

        // Alice registers as a validator with 5000 stake
        ledger.registerValidator(aliceKey, 5000.0);

        // Give Alice some initial funds (simulate mining reward)
        TransactionOutput genesisUTXO{
            "genesis",
            0,
            aliceAddr,
            10000.0
        };

        // Create a transaction from Alice to Bob
        std::vector<TransactionOutput> inputs = {genesisUTXO};
        std::string txId = ledger.createTransaction(aliceKey, bobAddr, 250.0, inputs);
        
        std::cout << "Created transaction: " << txId << std::endl;

        // Check Bob's balance
        auto bobUTXOs = ledger.getAddressUTXOs(bobAddr);
        double bobBalance = 0.0;
        for (const auto& utxo : bobUTXOs) {
            bobBalance += utxo.amount;
        }
        
        std::cout << "Bob's balance: " << bobBalance << std::endl;

        // Wait for some blocks to be created
        std::this_thread::sleep_for(std::chrono::seconds(60));

        // Print blockchain info
        auto latestBlock = ledger.getLatestBlock();
        if (latestBlock) {
            std::cout << "Latest block: #" << latestBlock->blockNumber 
                      << " with " << latestBlock->transactions.size() 
                      << " transactions" << std::endl;
        }

        std::cout << "Total transactions in DAG: " << ledger.getDAGSize() << std::endl;
        std::cout << "Blockchain height: " << ledger.getBlockchainHeight() << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
// ---------------------------
// 8. Smart Contract System
// ---------------------------
/**
 * Simple smart contract support
 * Supports execution of custom logic during transaction validation
 */
class SmartContract {
public:
    enum class ContractType {
        SIMPLE_TRANSFER,
        TIME_LOCK,
        MULTI_SIG,
        CUSTOM
    };

private:
    std::string contractId;
    ContractType type;
    std::string code;
    std::unordered_map<std::string, std::string> state;
    std::mutex contractMutex;

public:
    SmartContract(ContractType cType, std::string contractCode) 
        : type(cType), code(std::move(contractCode)) 
    {
        contractId = CryptoHelper::sha256(code + std::to_string(static_cast<int>(type)));
    }

    // Executes contract logic during transaction processing
    bool execute(const Transaction& tx, const std::unordered_map<std::string, TransactionOutput>& utxoSet) {
        std::lock_guard<std::mutex> lock(contractMutex);

        switch (type) {
            case ContractType::SIMPLE_TRANSFER:
                return true; // Basic transfer always valid if inputs/outputs balance

            case ContractType::TIME_LOCK:
                return validateTimeLock(tx);

            case ContractType::MULTI_SIG:
                return validateMultiSig(tx, utxoSet);

            case ContractType::CUSTOM:
                return executeCustom(tx);

            default:
                return false;
        }
    }

    // Get contract state value
    std::optional<std::string> getState(const std::string& key) const {
        std::lock_guard<std::mutex> lock(contractMutex);
        
        auto it = state.find(key);
        if (it != state.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Set contract state value
    void setState(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(contractMutex);
        state[key] = value;
    }

    // Get contract ID
    const std::string& getId() const { return contractId; }

    // Get contract type
    ContractType getType() const { return type; }

private:
    // Time lock validation - checks if transaction is allowed to execute based on time
    bool validateTimeLock(const Transaction& tx) {
        auto lockTimeStr = getState("unlock_time");
        if (!lockTimeStr) {
            return false; // No unlock time found
        }

        std::int64_t unlockTime = std::stoll(*lockTimeStr);
        std::int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        return currentTime >= unlockTime;
    }

    // Multi-signature validation
    bool validateMultiSig(const Transaction& tx, const std::unordered_map<std::string, TransactionOutput>& utxoSet) {
        auto requiredSignaturesStr = getState("required_signatures");
        if (!requiredSignaturesStr) {
            return false;
        }

        int requiredSignatures = std::stoi(*requiredSignaturesStr);
        
        // Get approved public keys
        auto approvedKeysStr = getState("approved_keys");
        if (!approvedKeysStr) {
            return false;
        }

        std::unordered_set<std::string> approvedKeys;
        std::stringstream ss(*approvedKeysStr);
        std::string key;
        while (std::getline(ss, key, ',')) {
            approvedKeys.insert(key);
        }

        // Count valid signatures from approved keys
        int validSignatures = 0;
        std::unordered_set<std::string> usedKeys;

        for (const auto& input : tx.getInputs()) {
            if (approvedKeys.count(input.publicKey) > 0 && usedKeys.count(input.publicKey) == 0) {
                // Verify this signature is valid
                std::string dataToVerify = input.utxoId + tx.getId();
                bool validSig = CryptoHelper::verifySignature(
                    input.publicKey,
                    hexToBytes(input.signature),
                    dataToVerify
                );
                
                if (validSig) {
                    validSignatures++;
                    usedKeys.insert(input.publicKey);
                }
            }
        }

        return validSignatures >= requiredSignatures;
    }

    // Execute custom contract code
    bool executeCustom(const Transaction& tx) {
        // In a real system, this might parse and execute script code
        // For simplicity, we'll just check a flag in the state
        auto enabledStr = getState("enabled");
        return enabledStr && *enabledStr == "true";
    }
};

/**
 * Manages all smart contracts in the system
 */
class ContractManager {
private:
    std::unordered_map<std::string, SmartContract> contracts;
    std::mutex contractsMutex;

public:
    // Register a new contract
    std::string registerContract(SmartContract::ContractType type, const std::string& code) {
        SmartContract contract(type, code);
        std::string id = contract.getId();
        
        std::lock_guard<std::mutex> lock(contractsMutex);
        contracts[id] = std::move(contract);
        
        return id;
    }

    // Get a contract by ID
    std::optional<std::reference_wrapper<SmartContract>> getContract(const std::string& id) {
        std::lock_guard<std::mutex> lock(contractsMutex);
        
        auto it = contracts.find(id);
        if (it != contracts.end()) {
            return std::ref(it->second);
        }
        return std::nullopt;
    }

    // Execute a contract
    bool executeContract(const std::string& id, const Transaction& tx, 
                        const std::unordered_map<std::string, TransactionOutput>& utxoSet) 
    {
        auto contractOpt = getContract(id);
        if (!contractOpt) {
            return false;
        }
        
        return contractOpt->get().execute(tx, utxoSet);
    }
    
    // Get all contract IDs
    std::vector<std::string> getAllContractIds() const {
        std::lock_guard<std::mutex> lock(contractsMutex);
        
        std::vector<std::string> ids;
        ids.reserve(contracts.size());
        
        for (const auto& [id, _] : contracts) {
            ids.push_back(id);
        }
        
        return ids;
    }
};

// ---------------------------
// 9. Network Layer
// ---------------------------
/**
 * Simple peer-to-peer network for node communication
 * In a real implementation, this would use sockets or a library like ZeroMQ
 */
class NetworkMessage {
public:
    enum class MessageType {
        TRANSACTION,
        BLOCK,
        PEER_DISCOVERY,
        TRANSACTION_REQUEST,
        BLOCK_REQUEST
    };

    MessageType type;
    std::string payload;
    std::string sender;
    std::int64_t timestamp;

    NetworkMessage(MessageType t, std::string p, std::string s)
        : type(t), payload(std::move(p)), sender(std::move(s))
    {
        timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }

    // Serialize message for network transmission
    std::string serialize() const {
        std::stringstream ss;
        ss << static_cast<int>(type) << "|"
           << payload << "|"
           << sender << "|"
           << timestamp;
        return ss.str();
    }

    // Deserialize message from network
    static NetworkMessage deserialize(const std::string& data) {
        std::stringstream ss(data);
        std::string token;
        
        std::getline(ss, token, '|');
        MessageType type = static_cast<MessageType>(std::stoi(token));
        
        std::getline(ss, token, '|');
        std::string payload = token;
        
        std::getline(ss, token, '|');
        std::string sender = token;
        
        NetworkMessage msg(type, payload, sender);
        
        std::getline(ss, token, '|');
        msg.timestamp = std::stoll(token);
        
        return msg;
    }
};

class NetworkNode {
private:
    std::string nodeId;
    std::unordered_set<std::string> peers;
    std::function<void(const NetworkMessage&)> messageHandler;
    std::thread networkThread;
    std::atomic<bool> running{false};
    std::mutex peersMutex;
    
    // Queue of incoming messages
    std::vector<NetworkMessage> messageQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;

    // Simulate network communication
    void networkWorker() {
        while (running) {
            // Process message queue
            std::unique_lock<std::mutex> lock(queueMutex);
            if (messageQueue.empty()) {
                // Wait for new messages with timeout
                queueCV.wait_for(lock, std::chrono::seconds(1));
            } else {
                // Get next message
                NetworkMessage msg = messageQueue.back();
                messageQueue.pop_back();
                lock.unlock();
                
                // Handle message
                if (messageHandler) {
                    messageHandler(msg);
                }
            }
        }
    }

public:
    NetworkNode(std::string id) : nodeId(std::move(id)) {
        // Generate random node ID if not provided
        if (nodeId.empty()) {
            std::random_device rd;
            std::mt19937 rng(rd());
            std::uniform_int_distribution<> dist(10000, 99999);
            nodeId = "node_" + std::to_string(dist(rng));
        }
    }

    ~NetworkNode() {
        stop();
    }

    // Start node's network thread
    void start() {
        running = true;
        networkThread = std::thread(&NetworkNode::networkWorker, this);
    }

    // Stop node's network thread
    void stop() {
        running = false;
        if (networkThread.joinable()) {
            networkThread.join();
        }
    }

    // Set message handler callback
    void setMessageHandler(std::function<void(const NetworkMessage&)> handler) {
        messageHandler = std::move(handler);
    }

    // Connect to another peer
    bool addPeer(const std::string& peerId) {
        std::lock_guard<std::mutex> lock(peersMutex);
        if (peerId != nodeId) {
            peers.insert(peerId);
            return true;
        }
        return false;
    }

    // Remove a peer
    bool removePeer(const std::string& peerId) {
        std::lock_guard<std::mutex> lock(peersMutex);
        return peers.erase(peerId) > 0;
    }

    // Broadcast message to all peers
    void broadcast(NetworkMessage::MessageType type, const std::string& payload) {
        std::lock_guard<std::mutex> lockPeers(peersMutex);
        NetworkMessage msg(type, payload, nodeId);
        
        for (const auto& peer : peers) {
            // In a real implementation, this would send over network
            // Here we just queue the message for simulation
            receiveMessage(msg);
        }
    }

    // Send message to specific peer
    void sendTo(const std::string& peerId, NetworkMessage::MessageType type, const std::string& payload) {
        std::lock_guard<std::mutex> lockPeers(peersMutex);
        if (peers.count(peerId) > 0) {
            NetworkMessage msg(type, payload, nodeId);
            // In a real implementation, send to specific peer
            receiveMessage(msg);
        }
    }

    // Handle incoming message
    void receiveMessage(const NetworkMessage& msg) {
        std::lock_guard<std::mutex> lock(queueMutex);
        messageQueue.push_back(msg);
        queueCV.notify_one();
    }

    // Get node ID
    const std::string& getId() const { return nodeId; }

    // Get peers
    std::unordered_set<std::string> getPeers() const {
        std::lock_guard<std::mutex> lock(peersMutex);
        return peers;
    }
};

// ---------------------------
// 10. Enhanced HybridLedger
// ---------------------------
/**
 * An enhanced version of the HybridLedger class with 
 * smart contract and networking support
 */
class EnhancedHybridLedger : public HybridLedger {
private:
    ContractManager contractManager;
    NetworkNode network;
    
    // Handle network messages
    void processNetworkMessage(const NetworkMessage& msg) {
        try {
            switch (msg.type) {
                case NetworkMessage::MessageType::TRANSACTION: {
                    // Deserialize and add transaction
                    // In a real system, this would involve proper serialization
                    auto txOpt = getTransaction(msg.payload);
                    if (!txOpt) {
                        // This is simplified; in reality we'd deserialize the full tx
                        std::cout << "Received transaction: " << msg.payload << std::endl;
                    }
                    break;
                }
                
                case NetworkMessage::MessageType::BLOCK: {
                    // Deserialize and add block
                    std::cout << "Received block: " << msg.payload << std::endl;
                    break;
                }
                
                case NetworkMessage::MessageType::PEER_DISCOVERY: {
                    // Add new peer to network
                    network.addPeer(msg.payload);
                    std::cout << "Discovered peer: " << msg.payload << std::endl;
                    break;
                }
                
                case NetworkMessage::MessageType::TRANSACTION_REQUEST: {
                    // Respond with requested transaction
                    auto txOpt = getTransaction(msg.payload);
                    if (txOpt) {
                        // Simplified; would serialize full tx in reality
                        network.sendTo(msg.sender, NetworkMessage::MessageType::TRANSACTION, 
                                    msg.payload);
                    }
                    break;
                }
                
                case NetworkMessage::MessageType::BLOCK_REQUEST: {
                    // Respond with requested block
                    // This is simplified
                    std::cout << "Block requested: " << msg.payload << std::endl;
                    break;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error processing message: " << e.what() << std::endl;
        }
    }
    
public:
    EnhancedHybridLedger() : HybridLedger(), network("node1") {
        // Set up network message handler
        network.setMessageHandler([this](const NetworkMessage& msg) {
            this->processNetworkMessage(msg);
        });
        
        // Start network services
        network.start();
    }
    
    ~EnhancedHybridLedger() {
        network.stop();
    }
    
    // Create a new smart contract
    std::string createContract(SmartContract::ContractType type, const std::string& code) {
        return contractManager.registerContract(type, code);
    }
    
    // Execute a contract with a transaction
    bool executeContract(const std::string& contractId, const Transaction& tx) {
        return contractManager.executeContract(contractId, tx, getUTXOSetCopy());
    }
    
    // Get UTXO set copy for contract execution
    std::unordered_map<std::string, TransactionOutput> getUTXOSetCopy() const {
        // This would be implemented to provide a copy of the current UTXO set
        // For simplicity, we're returning an empty set here
        return {};
    }
    
    // Create and broadcast a transaction
    std::string createAndBroadcastTransaction(
        const CryptoHelper::ECKeyPtr& senderKey,
        const std::string& recipient,
        double amount,
        const std::vector<TransactionOutput>& inputs) 
    {
        std::string txId = createTransaction(senderKey, recipient, amount, inputs);
        
        // Broadcast to network
        network.broadcast(NetworkMessage::MessageType::TRANSACTION, txId);
        
        return txId;
    }
    
    // Create a time-locked transaction
    std::string createTimeLockTransaction(
        const CryptoHelper::ECKeyPtr& senderKey,
        const std::string& recipient,
        double amount,
        const std::vector<TransactionOutput>& inputs,
        std::int64_t unlockTime)
    {
        std::string txId = createTransaction(senderKey, recipient, amount, inputs);
        
        // Create time-lock contract
        std::string code = "time_lock:" + recipient + ":" + std::to_string(amount);
        std::string contractId = contractManager.registerContract(
            SmartContract::ContractType::TIME_LOCK, code);
            
        auto contractOpt = contractManager.getContract(contractId);
        if (contractOpt) {
            contractOpt->get().setState("unlock_time", std::to_string(unlockTime));
            contractOpt->get().setState("transaction_id", txId);
        }
        
        return txId;
    }
    
    // Create a multi-signature transaction
    std::string createMultiSigTransaction(
        const CryptoHelper::ECKeyPtr& senderKey,
        const std::string& recipient,
        double amount,
        const std::vector<TransactionOutput>& inputs,
        const std::vector<std::string>& approvedKeys,
        int requiredSignatures)
    {
        std::string txId = createTransaction(senderKey, recipient, amount, inputs);
        
        // Create multi-sig contract
        std::string code = "multi_sig:" + recipient + ":" + std::to_string(amount);
        std::string contractId = contractManager.registerContract(
            SmartContract::ContractType::MULTI_SIG, code);
            
        auto contractOpt = contractManager.getContract(contractId);
        if (contractOpt) {
            // Join approved keys with commas
            std::stringstream ss;
            for (size_t i = 0; i < approvedKeys.size(); ++i) {
                if (i > 0) ss << ",";
                ss << approvedKeys[i];
            }
            
            contractOpt->get().setState("approved_keys", ss.str());
            contractOpt->get().setState("required_signatures", std::to_string(requiredSignatures));
            contractOpt->get().setState("transaction_id", txId);
        }
        
        return txId;
    }
    
    // Add a network peer
    bool addPeer(const std::string& peerId) {
        return network.addPeer(peerId);
    }
    
    // Broadcast block creation
    void broadcastBlock(const FinalityChain::Block& block) {
        // Simplified; would serialize block in reality
        network.broadcast(NetworkMessage::MessageType::BLOCK, block.blockHash);
    }
    
    // Get network node ID
    std::string getNodeId() const {
        return network.getId();
    }
    
    // Get network peers
    std::vector<std::string> getPeers() const {
        auto peerSet = network.getPeers();
        return std::vector<std::string>(peerSet.begin(), peerSet.end());
    }
};

// ---------------------------
// 11. Enhanced Example Usage
// ---------------------------

int enhancedMain() {
    try {
        // Initialize the enhanced hybrid ledger
        EnhancedHybridLedger ledger;
        
        std::cout << "Node ID: " << ledger.getNodeId() << std::endl;

        // Create some user key pairs
        auto aliceKey = CryptoHelper::generateKeyPair();
        auto bobKey = CryptoHelper::generateKeyPair();
        auto charlieKey = CryptoHelper::generateKeyPair();
        
        std::string aliceAddr = CryptoHelper::getPublicKeyHex(aliceKey);
        std::string bobAddr = CryptoHelper::getPublicKeyHex(bobKey);
        std::string charlieAddr = CryptoHelper::getPublicKeyHex(charlieKey);

        // Alice registers as a validator with 5000 stake
        ledger.registerValidator(aliceKey, 5000.0);

        // Give Alice some initial funds (simulate mining reward)
        TransactionOutput genesisUTXO{
            "genesis",
            0,
            aliceAddr,
            10000.0
        };

        // Create a standard transaction from Alice to Bob
        std::vector<TransactionOutput> inputs = {genesisUTXO};
        std::string standardTxId = ledger.createAndBroadcastTransaction(
            aliceKey, bobAddr, 250.0, inputs);
        
        std::cout << "Created standard transaction: " << standardTxId << std::endl;

        // Create a time-locked transaction from Alice to Charlie
        // that will unlock in 1 hour
        std::int64_t oneHour = 60 * 60 * 1000; // 1 hour in milliseconds
        std::int64_t unlockTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count() + oneHour;
        
        TransactionOutput aliceUTXO = ledger.getAddressUTXOs(aliceAddr)[0]; // Simplified
        
        std::string timeLockTxId = ledger.createTimeLockTransaction(
            aliceKey, charlieAddr, 500.0, {aliceUTXO}, unlockTime);
            
        std::cout << "Created time-locked transaction: " << timeLockTxId << std::endl;
        std::cout << "Will unlock at: " << unlockTime << std::endl;

        // Create a multi-signature transaction requiring 2 out of 3 signatures
        std::vector<std::string> approvedKeys = {aliceAddr, bobAddr, charlieAddr};
        
        aliceUTXO = ledger.getAddressUTXOs(aliceAddr)[0]; // Simplified
        
        std::string multiSigTxId = ledger.createMultiSigTransaction(
            aliceKey, bobAddr, 1000.0, {aliceUTXO}, approvedKeys, 2);
            
        std::cout << "Created multi-signature transaction: " << multiSigTxId << std::endl;

        // Create a simple smart contract
        std::string contractCode = "function transfer(from, to, amount) { "
                                  "  if (from.balance >= amount) { "
                                  "    from.balance -= amount; "
                                  "    to.balance += amount; "
                                  "    return true; "
                                  "  } "
                                  "  return false; "
                                  "}";
                                  
        std::string contractId = ledger.createContract(
            SmartContract::ContractType::CUSTOM, contractCode);
            
        std::cout << "Created smart contract: " << contractId << std::endl;

        // Connect to another peer (simplified simulation)
        ledger.addPeer("node2");
        
        std::cout << "Connected peers: ";
        for (const auto& peer : ledger.getPeers()) {
            std::cout << peer << " ";
        }
        std::cout << std::endl;

        // Wait for some blocks to be created
        std::cout << "Waiting for blocks to be created..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(10));

        // Print blockchain info
        auto latestBlock = ledger.getLatestBlock();
        if (latestBlock) {
            std::cout << "Latest block: #" << latestBlock->blockNumber 
                      << " with " << latestBlock->transactions.size() 
                      << " transactions" << std::endl;
                      
            // Broadcast block
            ledger.broadcastBlock(*latestBlock);
        }

        std::cout << "Total transactions in DAG: " << ledger.getDAGSize() << std::endl;
        std::cout << "Blockchain height: " << ledger.getBlockchainHeight() << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error in enhanced example: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

// Alternative main function to select example mode
int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "enhanced") {
        return enhancedMain();
    } else {
        std::cout << "Running basic example mode. Use 'enhanced' argument for advanced features.\n" << std::endl;
        return main(); // Call the original main
    }
}

    return 0;
}
