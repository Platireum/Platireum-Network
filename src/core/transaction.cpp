#include "transaction.h"
#include <algorithm>     // For std::sort
#include <stdexcept>     // For std::runtime_error
#include <iostream>      // For std::cerr in deserialize
#include <limits>        // For std::numeric_limits
#include <sstream>       // For std::stringstream
#include <nlohmann/json.hpp> // For JSON serialization/deserialization

// Use nlohmann::json for JSON operations
using json = nlohmann::json;

// --- Helper functions for JSON serialization/deserialization of structs ---


// --- Implementation of Transaction class functions ---

// Constructor for building a new transaction with flexible payload
Transaction::Transaction(TransactionType txType,
                         const std::string& creatorPubKey,
                         const std::string& dataPayload,
                         const std::vector<std::string>& parents,
                         const AIEngine::ProofOfComputation& proof)
    : type(txType), creatorPublicKey(creatorPubKey), payload(dataPayload), parentTxs(parents), aiProof(proof) {
    this->timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    this->id = calculateId(); // Calculate ID based on transaction contents
}

// Constructor for deserializing or recreating an already signed transaction
Transaction::Transaction(std::string id,
                         TransactionType txType,
                         long long ts,
                         std::string creatorPubKey,
                         std::string dataPayload,
                         std::vector<std::string> parents,
                         std::string sig,
                         AIEngine::ProofOfComputation proof)
    : id(std::move(id)), type(txType), timestamp(ts), creatorPublicKey(std::move(creatorPubKey)),
      payload(std::move(dataPayload)), parentTxs(std::move(parents)), signature(std::move(sig)), aiProof(std::move(proof)) {
    if (this->id.empty()) {
        throw TransactionError("Restored transaction has empty ID.");
    }
}
// New ID calculation function based on transaction contents
std::string Transaction::calculateId() {
    std::stringstream ss;
    ss << static_cast<int>(type) << timestamp << creatorPublicKey << payload;

    std::vector<std::string> sortedParents = parentTxs;
    std::sort(sortedParents.begin(), sortedParents.end());
    for (const auto& parent : sortedParents) {
        ss << parent;
    }

    if (type == TransactionType::AI_COMPUTATION_PROOF) {
        ss << aiProof.data_hash << aiProof.output_hash << aiProof.signature;
    }

    return CryptoHelper::sha256(ss.str());
}

// Sign the transaction with private key
void Transaction::sign(const CryptoHelper::ECKeyPtr& privateKey) {
    // Ensure ID is calculated before signing
    if (id.empty()) {
        this->id = calculateId();
    }
    std::vector<unsigned char> signatureBytes = CryptoHelper::signData(privateKey, this->id);
    this->signature = CryptoHelper::bytesToHex(signatureBytes);
}

void Transaction::setPayload(const std::string& newPayload) {
    payload = newPayload;
    // Recalculate ID and hash if payload changes
    this->id = calculateId();
    // hash = calculateHash(); // No need to recalculate hash here, it's done on demand
}

// Verify the transaction signature
bool Transaction::verifySignature() const {
    if (creatorPublicKey.empty() || signature.empty() || id.empty()) {
        return false;
    }

    std::vector<unsigned char> signatureBytes = CryptoHelper::hexToBytes(signature);
    return CryptoHelper::verifySignature(creatorPublicKey, signatureBytes, id);
}

// Validate transaction
bool Transaction::validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const {
    // Verify signature for all transaction types
    if (!verifySignature()) {
        throw TransactionError("Transaction signature verification failed.");
    }

    // Re-calculate ID to ensure it matches the stored ID
    std::stringstream ssCheck;
    ssCheck << static_cast<int>(type) << timestamp << creatorPublicKey << payload;
    if (type == TransactionType::AI_COMPUTATION_PROOF) {
        ssCheck << aiProof.data_hash << aiProof.output_hash << aiProof.signature;
    }
    std::vector<std::string> sortedParents = parentTxs;
    std::sort(sortedParents.begin(), sortedParents.end());
    for (const auto& parent : sortedParents) {
        ssCheck << parent;
    }
    std::string calculatedId = CryptoHelper::sha256(ssCheck.str());
    if (calculatedId != id) {
        throw TransactionError("Transaction ID mismatch. Data tampered or invalid.");
    }

    // Specific validation logic based on transaction type
    if (type == TransactionType::VALUE_TRANSFER) {
        // For VALUE_TRANSFER, parse inputs and outputs from payload
        json payload_json = json::parse(payload);
        std::vector<TransactionInput> inputs = payload_json.at("inputs").get<std::vector<TransactionInput>>();
        std::vector<TransactionOutput> outputs = payload_json.at("outputs").get<std::vector<TransactionOutput>>();

        if (inputs.empty() && outputs.empty()) {
            throw TransactionError("VALUE_TRANSFER transaction must have at least one input or one output.");
        }
        // Coinbase transactions (no inputs, one output)
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
            throw TransactionError("VALUE_TRANSFER transaction must have at least one output.");
        }

        std::unordered_set<std::string> spentUtxosInThisTx;
        for (const auto& input : inputs) {
            if (spentUtxosInThisTx.count(input.transactionId + ":" + std::to_string(input.outputIndex))) {
                throw TransactionError("Transaction attempts to double-spend UTXO within itself: " + input.transactionId + ":" + std::to_string(input.outputIndex));
            }
            spentUtxosInThisTx.insert(input.transactionId + ":" + std::to_string(input.outputIndex));
        }

        long double totalInputAmount = 0;
        for (const auto& input : inputs) {
            std::string utxo_id = input.transactionId + ":" + std::to_string(input.outputIndex);
            auto it = utxoSet.find(utxo_id);
            if (it == utxoSet.end()) {
                throw TransactionError("Referenced UTXO not found: " + utxo_id);
            }
            const TransactionOutput& utxo = it->second;

            // Verify input signature against the UTXO owner's public key
            // The data that was signed for the input is the concatenation of the referenced UTXO's transactionId, outputIndex, and the current transaction's ID.
            std::string signed_data_for_input = input.transactionId + ":" + std::to_string(input.outputIndex) + ":" + this->id;
            if (!CryptoHelper::verifySignature(input.publicKey, CryptoHelper::hexToBytes(input.signature), signed_data_for_input)) {
                throw TransactionError("Invalid signature for input: " + utxo_id);
            }
            totalInputAmount += utxo.amount;
        }

        long double totalOutputAmount = 0;
        for (const auto& output : outputs) {
            if (output.amount <= 0) {
                throw TransactionError("Transaction output amount must be positive.");
            }
            totalOutputAmount += output.amount;
        }

        if (totalInputAmount < totalOutputAmount) {
            throw TransactionError("Total input amount is less than total output amount.");
        }
        // Fees are implicitly (totalInputAmount - totalOutputAmount)

    } else if (type == TransactionType::SMART_CONTRACT_CALL) {
        // Basic validation: ensure payload is valid JSON and contains necessary fields
        try {
            json contract_call_data = json::parse(payload);
            if (!contract_call_data.contains("contractAddress") || !contract_call_data.contains("method") || !contract_call_data.contains("args")) {
                throw TransactionError("SMART_CONTRACT_CALL payload missing required fields.");
            }
        } catch (const json::parse_error& e) {
            throw TransactionError("SMART_CONTRACT_CALL payload is not valid JSON: " + std::string(e.what()));
        }
    } else if (type == TransactionType::AI_COMPUTATION_PROOF) {
        // Basic validation: ensure payload is valid JSON and contains necessary fields
        try {
            json proof_data = json::parse(payload);
            if (!proof_data.contains("proof") || !proof_data.contains("usefulWorkHash") || !proof_data.contains("computeScore")) {
                throw TransactionError("AI_COMPUTATION_PROOF payload missing required fields.");
            }
            // Further validation involves verifying the proof itself using AIEngine.
            double computeScore = proof_data.at("computeScore").get<double>();
            std::string usefulWorkHash = proof_data.at("usefulWorkHash").get<std::string>();

            // Create a temporary AIEngine instance for verification
            AIEngine ai_engine;
            if (!ai_engine.verify_proof(usefulWorkHash, computeScore, aiProof)) {
                throw TransactionError("AI_COMPUTATION_PROOF verification failed.");
            }
        } catch (const json::parse_error& e) {
            throw TransactionError("AI_COMPUTATION_PROOF payload is not valid JSON: " + std::string(e.what()));
        }
    }
    // Add more validation for other transaction types as needed

    return true;
}

// Helper method to create a signed TransactionInput for financial transactions
TransactionInput Transaction::createSignedInput(
    const std::string& utxoId,
    const CryptoHelper::ECKeyPtr& privateKey,
    const std::string& currentTxId
) {
    size_t colonPos = utxoId.find(":");
    if (colonPos == std::string::npos) {
        throw TransactionError("Invalid UTXO ID format: " + utxoId);
    }
    std::string transactionId = utxoId.substr(0, colonPos);
    int outputIndex = std::stoi(utxoId.substr(colonPos + 1));

    std::string ownerPublicKey = CryptoHelper::getPublicKeyHex(privateKey);
    // The data to be signed is the concatenation of the transactionId, outputIndex, and the currentTxId
    std::string dataToSign = transactionId + ":" + std::to_string(outputIndex) + ":" + currentTxId; // This `currentTxId` is actually the hash of the transaction that *contains* this input, which is correct.
    std::vector<unsigned char> signatureBytes = CryptoHelper::signData(privateKey, dataToSign);
    std::string signature = CryptoHelper::bytesToHex(signatureBytes);

    return TransactionInput{transactionId, outputIndex, signature, ownerPublicKey};
}

// Serialize transaction to JSON
std::string Transaction::getHashForSigningInputs() const {
    // This hash should represent the transaction's unique identity for input signing purposes.
    // It should be stable and not change after the transaction is created and its ID is set.
    // Using the transaction's ID itself is the most straightforward way to achieve this.
    return id;
}

const std::vector<TransactionInput>& Transaction::getInputs() const {
    if (type != TransactionType::VALUE_TRANSFER) {
        static const std::vector<TransactionInput> emptyInputs;
        return emptyInputs;
    }
    try {
        json payload_json = json::parse(payload);
        static std::vector<TransactionInput> inputs_cache; // Cache to avoid re-parsing
        inputs_cache = payload_json.at("inputs").get<std::vector<TransactionInput>>();
        return inputs_cache;
    } catch (const json::parse_error& e) {
        throw TransactionError("Failed to parse inputs from payload: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw TransactionError("Error getting inputs from payload: " + std::string(e.what()));
    }
}

const std::vector<TransactionOutput>& Transaction::getOutputs() const {
    if (type != TransactionType::VALUE_TRANSFER) {
        static const std::vector<TransactionOutput> emptyOutputs;
        return emptyOutputs;
    }
    try {
        json payload_json = json::parse(payload);
        static std::vector<TransactionOutput> outputs_cache; // Cache to avoid re-parsing
        outputs_cache = payload_json.at("outputs").get<std::vector<TransactionOutput>>();
        return outputs_cache;
    } catch (const json::parse_error& e) {
        throw TransactionError("Failed to parse outputs from payload: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw TransactionError("Error getting outputs from payload: " + std::string(e.what()));
    }
}

std::string Transaction::serialize() const {
    json j;
    j["id"] = id;
    j["type"] = transactionTypeToString(type);
    j["timestamp"] = timestamp;
    j["creatorPublicKey"] = creatorPublicKey;
    j["payload"] = payload;
    j["parentTxs"] = parentTxs;
    j["signature"] = signature;
    if (type == TransactionType::AI_COMPUTATION_PROOF) {
        j["aiProof"] = {
            {"data_hash", aiProof.data_hash},
            {"output_hash", aiProof.output_hash},
            {"signature", aiProof.signature}
        };
    }
    return j.dump();
}

// Deserialize transaction from JSON
std::shared_ptr<Transaction> Transaction::deserialize(const std::string& jsonString) {
    try {
        json j = json::parse(jsonString);
        TransactionType type_val = stringToTransactionType(j.at("type").get<std::string>());
        std::string id_val = j.at("id").get<std::string>();
        long long timestamp_val = j.at("timestamp").get<long long>();
        std::string creatorPublicKey_val = j.at("creatorPublicKey").get<std::string>();
        std::string payload_val = j.at("payload").get<std::string>();
        std::vector<std::string> parentTxs_val = j.at("parentTxs").get<std::vector<std::string>>();
        std::string signature_val = j.at("signature").get<std::string>();
        AIEngine::ProofOfComputation aiProof_val;
        if (type_val == TransactionType::AI_COMPUTATION_PROOF && j.contains("aiProof")) {
            aiProof_val.data_hash = j.at("aiProof").at("data_hash").get<std::string>();
            aiProof_val.output_hash = j.at("aiProof").at("output_hash").get<std::string>();
            aiProof_val.signature = j.at("aiProof").at("signature").get<std::string>();
        }

        return std::make_shared<Transaction>(id_val, type_val, timestamp_val, creatorPublicKey_val, payload_val, parentTxs_val, signature_val, aiProof_val);
    } catch (const json::parse_error& e) {
        std::cerr << "JSON parse error in Transaction::deserialize: " << e.what() << std::endl;
        return nullptr;
    } catch (const std::exception& e) {
        std::cerr << "Error in Transaction::deserialize: " << e.what() << std::endl;
        return nullptr;
    }
}

// Provides a human-readable string representation of the transaction
std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "Transaction ID: " << id.substr(0, 16) << "...\n"
       << "  Type: " << transactionTypeToString(type) << "\n"
       << "  Timestamp: " << timestamp << "\n"
       << "  Creator: " << creatorPublicKey.substr(0, 16) << "...\n"
       << "  Payload: " << payload << "\n"
       << "  Parents: ";
    if (parentTxs.empty()) {
        ss << "None\n";
    } else {
        for (const auto& parent : parentTxs) {
            ss << parent.substr(0, 16) << "... ";
        }
        ss << "\n";
    }
    ss << "  Signature: " << signature.substr(0, 16) << "...\n";
    return ss.str();
}

// Converts TransactionType enum to string representation
std::string Transaction::transactionTypeToString(TransactionType type) {
    switch (type) {
        case TransactionType::VALUE_TRANSFER: return "VALUE_TRANSFER";
        case TransactionType::SMART_CONTRACT_CALL: return "SMART_CONTRACT_CALL";
        case TransactionType::AI_COMPUTATION_PROOF: return "AI_COMPUTATION_PROOF";
        default: return "UNKNOWN";
    }
}

// Converts string to TransactionType enum
TransactionType Transaction::stringToTransactionType(const std::string& typeStr) {
    if (typeStr == "VALUE_TRANSFER") return TransactionType::VALUE_TRANSFER;
    if (typeStr == "SMART_CONTRACT_CALL") return TransactionType::SMART_CONTRACT_CALL;
    if (typeStr == "AI_COMPUTATION_PROOF") return TransactionType::AI_COMPUTATION_PROOF;
    return TransactionType::VALUE_TRANSFER; // Default or error case
}

