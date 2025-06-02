#include "block.h"
#include <sstream>
#include <iomanip> // For std::hex, std::setw, std::setfill

// We'll need CryptoHelper for hashing block contents
#include "crypto_helper.h"

// Static instance for CryptoHelper, or pass it around
// For simplicity in Block, we'll create a local instance,
// but for performance, a shared instance would be better.
static CryptoHelper blockCryptoHelper;


Block::Block(const std::string& hash_val,
             int h,
             const std::string& prevHash,
             const std::string& dagRoot,
             int n,
             const std::string& minter,
             long long ts,
             const std::string& sig)
    : hash(hash_val), height(h), previousHash(prevHash), dagRootHash(dagRoot),
      nonce(n), minterId(minter), timestamp(ts), signature(sig) {
    // If hash_val is "N/A" or empty, calculate it in the constructor
    if (hash == "N/A" || hash.empty()) {
        this->hash = calculateHash();
    }
}

// Private helper to calculate the block's hash
std::string Block::calculateHash() const {
    // Hash includes: height, previousHash, dagRootHash, nonce, minterId, timestamp, and hashes of all transactions.
    // For simplicity, we'll just concatenate essential fields and hash them.
    // In a real blockchain, you'd calculate a Merkle root of transactions.

    std::stringstream ss;
    ss << height << previousHash << dagRootHash << nonce << minterId << timestamp;

    for (const auto& tx : transactions) {
        ss << tx->getId(); // Add transaction IDs to the hash input
    }
    
    return blockCryptoHelper.sha256(ss.str());
}

void Block::addTransaction(std::shared_ptr<Transaction> tx) {
    transactions.push_back(tx);
    // After adding a transaction, the block's hash *should* be re-calculated
    // if the block is still being built. For simplicity, we don't recalculate here.
    // The hash is usually finalized when mining completes.
}

std::string Block::toString() const {
    std::stringstream ss;
    ss << "Block Hash: " << hash.substr(0, 12) << "...\n"
       << "Height: " << height << "\n"
       << "Previous Hash: " << previousHash.substr(0, 12) << "...\n"
       << "DAG Root Hash: " << dagRootHash.substr(0, 12) << "...\n"
       << "Nonce: " << nonce << "\n"
       << "Minter ID: " << minterId.substr(0, 12) << "...\n"
       << "Timestamp: " << timestamp << "\n"
       << "Signature: " << signature.substr(0, 12) << "...\n"
       << "Transactions (" << transactions.size() << "):\n";
    for (const auto& tx : transactions) {
        ss << "  - " << tx->toString() << "\n";
    }
    return ss.str();
}

std::string Block::serialize() const {
    // For simplicity, using string concatenation for JSON.
    // A proper JSON library (like nlohmann/json) is highly recommended for real applications.
    std::string txs_json = "[";
    bool first_tx = true;
    for (const auto& tx : transactions) {
        if (!first_tx) {
            txs_json += ",";
        }
        txs_json += tx->serialize();
        first_tx = false;
    }
    txs_json += "]";

    std::stringstream ss;
    ss << "{"
       << "\"hash\":\"" << hash << "\","
       << "\"height\":" << height << ","
       << "\"previousHash\":\"" << previousHash << "\","
       << "\"dagRootHash\":\"" << dagRootHash << "\","
       << "\"nonce\":" << nonce << ","
       << "\"minterId\":\"" << minterId << "\","
       << "\"timestamp\":" << timestamp << ","
       << "\"signature\":\"" << signature << "\","
       << "\"transactions\":" << txs_json
       << "}";
    return ss.str();
}

std::shared_ptr<Block> Block::deserialize(const std::string& jsonString) {
    // This is a very rudimentary JSON parser.
    // In a real application, use a robust JSON library (e.g., nlohmann/json).
    // This implementation assumes a specific, simple JSON structure and might fail on malformed input.

    std::string currentKey;
    std::string currentValue;
    bool inKey = false;
    bool inValue = false;
    bool inString = false;
    bool escaped = false;

    std::string hash_val, prevHash, dagRoot, minter, sig;
    int h = 0, n = 0;
    long long ts = 0;
    std::vector<std::shared_ptr<Transaction>> txs;
    std::string transactions_json_segment;

    // Find key-value pairs (simplified)
    size_t pos = 0;
    size_t lastPos = 0;

    auto extract_value = [&](const std::string& key) {
        size_t key_start = jsonString.find("\"" + key + "\":", pos);
        if (key_start == std::string::npos) return std::string();

        size_t val_start_quote = jsonString.find("\"", key_start + key.length() + 3);
        if (val_start_quote != std::string::npos) { // String value
            size_t val_end_quote = jsonString.find("\"", val_start_quote + 1);
            if (val_end_quote != std::string::npos) {
                return jsonString.substr(val_start_quote + 1, val_end_quote - (val_start_quote + 1));
            }
        } else { // Numeric or other unquoted value
            size_t val_start_num = key_start + key.length() + 3;
            size_t val_end_num = jsonString.find_first_of(",}", val_start_num);
            if (val_end_num != std::string::npos) {
                return jsonString.substr(val_start_num, val_end_num - val_start_num);
            }
        }
        return std::string();
    };
    
    // Find basic fields
    hash_val = extract_value("hash");
    if (!extract_value("height").empty()) h = std::stoi(extract_value("height"));
    prevHash = extract_value("previousHash");
    dagRoot = extract_value("dagRootHash");
    if (!extract_value("nonce").empty()) n = std::stoi(extract_value("nonce"));
    minter = extract_value("minterId");
    if (!extract_value("timestamp").empty()) ts = std::stoll(extract_value("timestamp"));
    sig = extract_value("signature");

    // Extract transactions array part (more complex, requires careful parsing)
    size_t tx_array_start = jsonString.find("\"transactions\":[");
    if (tx_array_start != std::string::npos) {
        tx_array_start += std::string("\"transactions\":").length(); // Move past "transactions":"
        
        int bracket_count = 0;
        size_t current_char_pos = tx_array_start;
        bool found_array_end = false;
        for (; current_char_pos < jsonString.length(); ++current_char_pos) {
            char c = jsonString[current_char_pos];
            if (c == '[') {
                bracket_count++;
            } else if (c == ']') {
                bracket_count--;
            }
            if (bracket_count == 0 && c == ']') {
                found_array_end = true;
                break;
            }
        }
        if (found_array_end) {
            transactions_json_segment = jsonString.substr(tx_array_start, current_char_pos - tx_array_start + 1);
        }
    }


    // Deserialize transactions from the extracted segment
    // This requires iterating through the array and deserializing each transaction
    if (!transactions_json_segment.empty() && transactions_json_segment != "[]") {
        size_t current_tx_pos = 1; // Skip initial '['
        while (current_tx_pos < transactions_json_segment.length()) {
            size_t tx_start = transactions_json_segment.find("{", current_tx_pos);
            if (tx_start == std::string::npos) break;

            int brace_count = 0;
            size_t tx_end = tx_start;
            bool found_tx_end = false;
            for (; tx_end < transactions_json_segment.length(); ++tx_end) {
                char c = transactions_json_segment[tx_end];
                if (c == '{') {
                    brace_count++;
                } else if (c == '}') {
                    brace_count--;
                }
                if (brace_count == 0 && c == '}') {
                    found_tx_end = true;
                    break;
                }
            }
            if (found_tx_end) {
                std::string single_tx_json = transactions_json_segment.substr(tx_start, tx_end - tx_start + 1);
                try {
                    txs.push_back(Transaction::deserialize(single_tx_json));
                } catch (const std::exception& e) {
                    // Log error for transaction deserialization but try to continue
                    std::cerr << "Warning: Failed to deserialize transaction within block: " << e.what() << std::endl;
                }
                current_tx_pos = tx_end + 1; // Move past current transaction
            } else {
                break; // Malformed JSON
            }
        }
    }


    std::shared_ptr<Block> block = std::make_shared<Block>(
        hash_val, h, prevHash, dagRoot, n, minter, ts, sig);
    
    // Add deserialized transactions to the block
    for (const auto& tx : txs) {
        block->addTransaction(tx);
    }
    
    // Recalculate hash to verify integrity (optional but good practice)
    if (block->calculateHash() != hash_val) {
        // This indicates data tampering or a deserialization issue
        std::cerr << "Warning: Deserialized block hash mismatch! Calculated: " 
                  << block->calculateHash().substr(0,12) << "..., Expected: " 
                  << hash_val.substr(0,12) << "..." << std::endl;
        // Depending on strictness, you might throw an error here.
    }

    return block;
}