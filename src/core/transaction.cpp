#include "transaction.h"
#include <algorithm>     // For std::sort
#include <stdexcept>     // For std::runtime_error
#include <iostream>      // For std::cerr in deserialize
#include <limits>        // For std::numeric_limits
#include <sstream>       // For std::stringstream

// Helper functions for deserialize to parse nested JSON objects without a library
namespace { // Anonymous namespace for local helper functions
    // Extracts string value from a key-value pair within a JSON segment
    std::string extract_string_value_local(const std::string& jsonSegment, const std::string& key) {
        size_t key_pos = jsonSegment.find("\"" + key + "\":");
        if (key_pos == std::string::npos) return std::string();
        size_t value_start = jsonSegment.find("\"", key_pos + key.length() + 3); // +3 for ":\"
        if (value_start == std::string::npos) return std::string();
        size_t value_end = jsonSegment.find("\"", value_start + 1);
        if (value_end == std::string::npos) return std::string();
        return jsonSegment.substr(value_start + 1, value_end - (value_start + 1));
    }

    // Extracts numeric (long long) value from a key-value pair within a JSON segment
    long long extract_numeric_value_local(const std::string& jsonSegment, const std::string& key) {
        size_t key_pos = jsonSegment.find("\"" + key + "\":");
        if (key_pos == std::string::npos) return 0;
        size_t value_start = key_pos + key.length() + 3; // +3 for ":"
        size_t value_end = jsonSegment.find_first_of(",}", value_start);
        if (value_end == std::string::npos) return 0;
        try {
            return std::stoll(jsonSegment.substr(value_start, value_end - value_start));
        }
        catch (const std::exception& e) {
            std::cerr << "Error parsing numeric value for key '" << key << "' from segment: " << e.what() << std::endl;
            return 0;
        }
    }
} // end anonymous namespace

// --- Implementation of TransactionOutput helper functions ---

// Constructor to create TransactionOutput
TransactionOutput::TransactionOutput(std::string txId, int outputIndex, std::string owner, long long amount)
    : txId(std::move(txId)), outputIndex(outputIndex), owner(std::move(owner)), amount(amount) {
    if (this->txId.empty() || this->owner.empty() || this->amount <= 0 || this->outputIndex < 0) {
        throw TransactionError("Invalid TransactionOutput data provided.");
    }
}

// Create unique identifier for UTXO
std::string TransactionOutput::getId() const {
    return txId + ":" + std::to_string(outputIndex);
}

// Serialize output data for transaction hash calculation
std::string TransactionOutput::serializeForTransactionHash() const {
    std::stringstream ss;
    ss << owner << ":" << amount;
    return ss.str();
}

// --- Implementation of TransactionInput helper functions ---

// Constructor to create TransactionInput
TransactionInput::TransactionInput(std::string utxoId, std::string signature, std::string publicKey)
    : utxoId(std::move(utxoId)), signature(std::move(signature)), publicKey(std::move(publicKey)) {
    if (this->utxoId.empty() || this->signature.empty() || this->publicKey.empty()) {
        throw TransactionError("Invalid TransactionInput data provided (empty fields).");
    }
}

// Serialize input for signing (what the sender signs)
std::string TransactionInput::serializeForSigning(const std::string& newTxId) const {
    return utxoId + ":" + newTxId;
}

// Serialize input for new transaction hash
std::string TransactionInput::serializeForTransactionHash() const {
    std::stringstream ss;
    ss << utxoId << ":" << signature << ":" << publicKey;
    return ss.str();
}

// --- Implementation of Transaction class functions ---

// New constructor based on transaction type and payload data
Transaction::Transaction(TransactionType txType,
    const std::string& creatorPubKey,
    const std::string& dataPayload,
    const std::vector<std::string>& parents)
    : type(txType), creatorPublicKey(creatorPubKey), payload(dataPayload), parentTxs(parents) {
    this->timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    calculateId(); // Calculate ID based on transaction contents
}

// Old constructor for backward compatibility (deprecated)
Transaction::Transaction(std::vector<TransactionInput> ins,
    std::vector<TransactionOutput> outs,
    std::vector<std::string> parents)
    : inputs(std::move(ins)), outputs(std::move(outs)), parentTxs(std::move(parents)) {

    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    createId();

    // After calculating txId, update utxoId for all outputs
    for (int i = 0; i < this->outputs.size(); ++i) {
        this->outputs[i].txId = this->txId;
        this->outputs[i].outputIndex = i;
    }
}

// Constructor for restoring existing transaction
Transaction::Transaction(std::vector<TransactionInput> ins,
    std::vector<TransactionOutput> outs,
    std::vector<std::string> parents,
    std::int64_t ts,
    std::string id)
    : inputs(std::move(ins)), outputs(std::move(outs)), parentTxs(std::move(parents)),
    timestamp(ts), txId(std::move(id)) {

    if (this->txId.empty()) {
        throw TransactionError("Restored transaction has empty ID.");
    }
}

// New ID calculation function based on transaction contents
void Transaction::calculateId() {
    std::stringstream ss;
    ss << static_cast<int>(type) << timestamp << creatorPublicKey << payload;

    std::vector<std::string> sortedParents = parentTxs;
    std::sort(sortedParents.begin(), sortedParents.end());
    for (const auto& parent : sortedParents) {
        ss << parent;
    }

    this->txId = CryptoHelper::sha256(ss.str());
}

// Old ID calculation function (for UTXO-based transactions)
void Transaction::createId() {
    std::stringstream ss;

    ss << timestamp;

    std::vector<TransactionInput> sortedInputs = inputs;
    std::sort(sortedInputs.begin(), sortedInputs.end(), [](const TransactionInput& a, const TransactionInput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
        });
    for (const auto& input : sortedInputs) {
        ss << input.serializeForTransactionHash();
    }

    std::vector<TransactionOutput> sortedOutputs = outputs;
    std::sort(sortedOutputs.begin(), sortedOutputs.end(), [](const TransactionOutput& a, const TransactionOutput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
        });
    for (const auto& output : sortedOutputs) {
        ss << output.serializeForTransactionHash();
    }

    std::vector<std::string> sortedParents = parentTxs;
    std::sort(sortedParents.begin(), sortedParents.end());
    for (const auto& parent : sortedParents) {
        ss << parent;
    }

    txId = CryptoHelper::sha256(ss.str());
}

// Sign the transaction with private key
void Transaction::sign(const CryptoHelper::ECKeyPtr& privateKey) {
    std::vector<unsigned char> signatureBytes = CryptoHelper::signData(privateKey, this->txId);
    this->signature = CryptoHelper::bytesToHex(signatureBytes);
}

// Verify the transaction signature
bool Transaction::verifySignature() const {
    if (creatorPublicKey.empty() || signature.empty()) {
        return false;
    }

    std::vector<unsigned char> signatureBytes = CryptoHelper::hexToBytes(signature);
    return CryptoHelper::verifySignature(creatorPublicKey, signatureBytes, txId);
}

// Validate transaction
bool Transaction::validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const {
    // For new transaction type, verify signature first
    if (type != TransactionType::UTXO) {
        if (!verifySignature()) {
            throw TransactionError("Transaction signature verification failed.");
        }
        return true; // Basic validation for non-UTXO transactions
    }

    // Original UTXO validation logic for backward compatibility
    std::stringstream ssCheck;
    ssCheck << timestamp;

    std::vector<TransactionInput> sortedInputsCheck = inputs;
    std::sort(sortedInputsCheck.begin(), sortedInputsCheck.end(), [](const TransactionInput& a, const TransactionInput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
        });
    for (const auto& input : sortedInputsCheck) {
        ssCheck << input.serializeForTransactionHash();
    }

    std::vector<TransactionOutput> sortedOutputsCheck = outputs;
    std::sort(sortedOutputsCheck.begin(), sortedOutputsCheck.end(), [](const TransactionOutput& a, const TransactionOutput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
        });
    for (const auto& output : sortedOutputsCheck) {
        ssCheck << output.serializeForTransactionHash();
    }

    std::vector<std::string> sortedParentsCheck = parentTxs;
    std::sort(sortedParentsCheck.begin(), sortedParentsCheck.end());
    for (const auto& parent : sortedParentsCheck) {
        ssCheck << parent;
    }

    std::string calculatedTxId = CryptoHelper::sha256(ssCheck.str());
    if (calculatedTxId != txId) {
        throw TransactionError("Transaction hash mismatch. Data tampered or invalid.");
    }

    if (inputs.empty() && outputs.empty()) {
        throw TransactionError("Transaction must have at least one input or one output.");
    }
    if (inputs.empty()) {
        if (outputs.size() != 1) {
            throw TransactionError("Coinbase transaction must have exactly one output.");
        }
        if (outputs[0].amount <= 0) {
            throw TransactionError("Coinbase output amount must be positive.");
        }
        return true;
    }
    if (outputs.empty()) {
        throw TransactionError("Transaction must have at least one output.");
    }

    std::unordered_set<std::string> spentUtxosInThisTx;
    for (const auto& input : inputs) {
        if (spentUtxosInThisTx.count(input.utxoId)) {
            throw TransactionError("Transaction attempts to double-spend UTXO within itself: " + input.utxoId);
        }
        spentUtxosInThisTx.insert(input.utxoId);
    }

    long long totalInputAmount = 0;
    for (const auto& input : inputs) {
        auto it = utxoSet.find(input.utxoId);
        if (it == utxoSet.end()) {
            throw TransactionError("Input UTXO not found in provided UTXO set: " + input.utxoId);
        }
        const TransactionOutput& referencedUtxo = it->second;

        if (input.publicKey != referencedUtxo.owner) {
            throw TransactionError("Input public key does not match UTXO owner for UTXO: " + input.utxoId);
        }

        std::string messageToVerify = input.serializeForSigning(txId);

        std::vector<unsigned char> signatureBytes = CryptoHelper::hexToBytes(input.signature);
        if (!CryptoHelper::verifySignature(input.publicKey, signatureBytes, messageToVerify)) {
            throw TransactionError("Invalid signature for input UTXO: " + input.utxoId);
        }

        totalInputAmount += referencedUtxo.amount;
    }

    long long totalOutputAmount = 0;
    for (const auto& output : outputs) {
        if (output.amount <= 0) {
            throw TransactionError("Transaction output amount must be positive.");
        }
        totalOutputAmount += output.amount;
    }

    if (totalInputAmount < totalOutputAmount) {
        throw TransactionError("Input amount " + std::to_string(totalInputAmount) +
            " is less than output amount " + std::to_string(totalOutputAmount));
    }

    return true;
}

// Helper function to create signed TransactionInput
TransactionInput Transaction::createSignedInput(
    const std::string& utxoId,
    const CryptoHelper::ECKeyPtr& privateKey,
    const std::string& currentTxId
) {
    std::string publicKeyHex = CryptoHelper::getPublicKeyHex(privateKey);

    std::string messageToSign = utxoId + ":" + currentTxId;

    std::vector<unsigned char> signatureBytes = CryptoHelper::signData(privateKey, messageToSign);
    std::string signatureHex = CryptoHelper::bytesToHex(signatureBytes);

    return TransactionInput(utxoId, signatureHex, publicKeyHex);
}

std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "TxId: " << txId.substr(0, std::min((size_t)12, txId.length())) << "...\n"
        << "Type: " << static_cast<int>(type) << "\n"
        << "Timestamp: " << timestamp << "\n"
        << "Creator: " << creatorPublicKey.substr(0, std::min((size_t)12, creatorPublicKey.length())) << "...\n"
        << "Payload: " << payload.substr(0, std::min((size_t)20, payload.length())) << "...\n"
        << "Signature: " << signature.substr(0, std::min((size_t)12, signature.length())) << "...\n"
        << "Parents: [";
    bool first_parent = true;
    for (const auto& p : parentTxs) {
        if (!first_parent) ss << ", ";
        ss << p.substr(0, std::min((size_t)8, p.length())) << "...";
        first_parent = false;
    }
    ss << "]\n"
        << "  Inputs (" << inputs.size() << "):\n";
    for (const auto& input : inputs) {
        ss << "    - UTXO: " << input.utxoId << ", Public Key: " << input.publicKey.substr(0, std::min((size_t)12, input.publicKey.length())) << "..., Signature: " << input.signature.substr(0, std::min((size_t)12, input.signature.length())) << "...\n";
    }
    ss << "  Outputs (" << outputs.size() << "):\n";
    for (const auto& output : outputs) {
        ss << "    - Owner: " << output.owner.substr(0, std::min((size_t)12, output.owner.length())) << "..., Amount: " << output.amount << "\n";
    }
    return ss.str();
}

// New serialize function for the updated transaction structure
std::string Transaction::serialize() const {
    // Build JSON string with new fields: type, creatorPublicKey, payload, signature
    std::string inputs_json = "[";
    bool first_input = true;
    for (const auto& input : inputs) {
        if (!first_input) {
            inputs_json += ",";
        }
        inputs_json += "{\"utxoId\":\"" + input.utxoId + "\","
            "\"signature\":\"" + input.signature + "\","
            "\"publicKey\":\"" + input.publicKey + "\"}";
        first_input = false;
    }
    inputs_json += "]";

    std::string outputs_json = "[";
    bool first_output = true;
    for (const auto& output : outputs) {
        if (!first_output) {
            outputs_json += ",";
        }
        outputs_json += "{\"txId\":\"" + output.txId + "\","
            "\"outputIndex\":" + std::to_string(output.outputIndex) + ","
            "\"owner\":\"" + output.owner + "\","
            "\"amount\":" + std::to_string(output.amount) + "}";
        first_output = false;
    }
    outputs_json += "]";

    std::string parents_json = "[";
    bool first_parent = true;
    for (const auto& parent : parentTxs) {
        if (!first_parent) {
            parents_json += ",";
        }
        parents_json += "\"" + parent + "\"";
        first_parent = false;
    }
    parents_json += "]";

    std::stringstream ss;
    ss << "{"
        << "\"txId\":\"" << txId << "\","
        << "\"type\":" << static_cast<int>(type) << ","
        << "\"timestamp\":" << timestamp << ","
        << "\"creatorPublicKey\":\"" << creatorPublicKey << "\","
        << "\"payload\":\"" << payload << "\","
        << "\"signature\":\"" << signature << "\","
        << "\"inputs\":" << inputs_json << ","
        << "\"outputs\":" << outputs_json << ","
        << "\"parentTxs\":" << parents_json
        << "}";
    return ss.str();
}

std::shared_ptr<Transaction> Transaction::deserialize(const std::string& jsonString) {
    std::string txId_val;
    TransactionType type_val = TransactionType::UTXO;
    std::int64_t timestamp_val = 0;
    std::string creatorPublicKey_val;
    std::string payload_val;
    std::string signature_val;
    std::vector<TransactionInput> inputs_val;
    std::vector<TransactionOutput> outputs_val;
    std::vector<std::string> parentTxs_val;

    // Extract basic fields
    txId_val = extract_string_value_local(jsonString, "txId");
    type_val = static_cast<TransactionType>(extract_numeric_value_local(jsonString, "type"));
    timestamp_val = extract_numeric_value_local(jsonString, "timestamp");
    creatorPublicKey_val = extract_string_value_local(jsonString, "creatorPublicKey");
    payload_val = extract_string_value_local(jsonString, "payload");
    signature_val = extract_string_value_local(jsonString, "signature");

    // Extract and parse inputs array
    size_t inputs_array_start = jsonString.find("\"inputs\":[");
    if (inputs_array_start != std::string::npos) {
        inputs_array_start += std::string("\"inputs\":").length();
        size_t inputs_array_end = jsonString.find("]", inputs_array_start);
        if (inputs_array_end != std::string::npos) {
            std::string inputs_segment = jsonString.substr(inputs_array_start, inputs_array_end - inputs_array_start);
            size_t current_pos = 0;
            while ((current_pos = inputs_segment.find("{", current_pos)) != std::string::npos) {
                size_t input_end = inputs_segment.find("}", current_pos);
                if (input_end != std::string::npos) {
                    std::string single_input_json = inputs_segment.substr(current_pos, input_end - current_pos + 1);

                    std::string utxoId = extract_string_value_local(single_input_json, "utxoId");
                    std::string signature = extract_string_value_local(single_input_json, "signature");
                    std::string publicKey = extract_string_value_local(single_input_json, "publicKey");

                    if (!utxoId.empty() && !signature.empty() && !publicKey.empty()) {
                        inputs_val.emplace_back(utxoId, signature, publicKey);
                    }
                    current_pos = input_end + 1;
                }
                else {
                    break;
                }
            }
        }
    }

    // Extract and parse outputs array
    size_t outputs_array_start = jsonString.find("\"outputs\":[");
    if (outputs_array_start != std::string::npos) {
        outputs_array_start += std::string("\"outputs\":").length();
        size_t outputs_array_end = jsonString.find("]", outputs_array_start);
        if (outputs_array_end != std::string::npos) {
            std::string outputs_segment = jsonString.substr(outputs_array_start, outputs_array_end - outputs_array_start);
            size_t current_pos = 0;
            while ((current_pos = outputs_segment.find("{", current_pos)) != std::string::npos) {
                size_t output_end = outputs_segment.find("}", current_pos);
                if (output_end != std::string::npos) {
                    std::string single_output_json = outputs_segment.substr(current_pos, output_end - current_pos + 1);

                    std::string txId_out = extract_string_value_local(single_output_json, "txId");
                    long long outputIndex_out = extract_numeric_value_local(single_output_json, "outputIndex");
                    std::string owner_out = extract_string_value_local(single_output_json, "owner");
                    long long amount_out = extract_numeric_value_local(single_output_json, "amount");

                    if (!owner_out.empty() && amount_out >= 0) {
                        outputs_val.emplace_back(txId_out, (int)outputIndex_out, owner_out, amount_out);
                    }
                    current_pos = output_end + 1;
                }
                else {
                    break;
                }
            }
        }
    }

    // Extract and parse parent transactions array
    size_t parents_array_start = jsonString.find("\"parentTxs\":[");
    if (parents_array_start != std::string::npos) {
        parents_array_start += std::string("\"parentTxs\":").length();
        size_t parents_array_end = jsonString.find("]", parents_array_start);
        if (parents_array_end != std::string::npos) {
            std::string parents_segment = jsonString.substr(parents_array_start, parents_array_end - parents_array_start);
            size_t current_pos = 0;
            while ((current_pos = parents_segment.find("\"", current_pos)) != std::string::npos) {
                size_t parent_end = parents_segment.find("\"", current_pos + 1);
                if (parent_end != std::string::npos) {
                    parentTxs_val.push_back(parents_segment.substr(current_pos + 1, parent_end - (current_pos + 1)));
                    current_pos = parent_end + 1;
                }
                else {
                    break;
                }
            }
        }
    }

    // Create transaction object based on type
    std::shared_ptr<Transaction> tx;
    if (type_val == TransactionType::UTXO) {
        // Use old constructor for UTXO transactions
        tx = std::make_shared<Transaction>(inputs_val, outputs_val, parentTxs_val, timestamp_val, txId_val);
    }
    else {
        // Use new constructor for other transaction types
        tx = std::make_shared<Transaction>(type_val, creatorPublicKey_val, payload_val, parentTxs_val);
        tx->timestamp = timestamp_val;
        tx->txId = txId_val;
        tx->signature = signature_val;
        tx->inputs = inputs_val;
        tx->outputs = outputs_val;
    }

    return tx;
}
