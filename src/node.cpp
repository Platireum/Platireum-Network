#include "node.h"
#include <iostream>
#include <stdexcept>
#include <algorithm> // For std::remove_if
#include <chrono>      // For timestamp
#include <random>      // For std::mt19937 and std::uniform_int_distribution
#include <limits>      // For std::numeric_limits
#include <cmath>       // For std::fmax and std::fmin
#include <nlohmann/json.hpp> // For JSON serialization/deserialization

// Use nlohmann::json for JSON operations
using json = nlohmann::json;

// Global random device for generating node IDs, etc.
std::random_device rd_node_cpp;
std::mt19937 gen_node_cpp(rd_node_cpp());

// --- Helper for simple random ID generation ---
std::string generateRandomId(size_t length = 16) {
    const std::string charset = "abcdef0123456789";
    std::string result;
    result.reserve(length);
    std::uniform_int_distribution<> distrib(0, charset.length() - 1);
    for (size_t i = 0; i < length; ++i) {
        result += charset[distrib(gen_node_cpp)];
    }
    return result;
}

// --- Constructor and Initialization ---

Node::Node(const std::string& id, const std::string& pubKey, CryptoHelper::ECKeyPtr privateKeyPtr, std::shared_ptr<ValidatorManager> vm)
    : nodeId(id), nodePublicKey(pubKey), nodePrivateKeyPtr(std::move(privateKeyPtr)), validatorManager(std::move(vm)) {
    log("Node " + nodeId.substr(0, 8) + "... created.");
}

void Node::log(const std::string& message) const {
    std::cout << "[Node " << nodeId.substr(0, 8) + "...] " << message << std::endl;
}

void Node::initialize() {
    log("Initializing node components...");

    keyGenerator = std::make_shared<KeyGenerator>();
    log("KeyGenerator initialized.");

    storageManager = std::make_shared<StorageManager>("node_data_" + nodeId);
    storageManager->initialize();
    log("StorageManager initialized.");

    std::vector<std::shared_ptr<Block>> loadedBlocks = storageManager->loadAllBlocks();
    if (!validatorManager) {
        validatorManager = std::make_shared<ValidatorManager>(); // Initialize ValidatorManager if not provided
    }
    finalityChain = std::make_shared<FinalityChain>(validatorManager); // Pass ValidatorManager to FinalityChain
    if (loadedBlocks.empty()) {
        log("No existing blocks found. Creating genesis block...");
        std::vector<std::string> genesis_tx_ids; // Empty vector
        std::shared_ptr<Block> genesisBlock = std::make_shared<Block>(
            "genesis_block_hash", // hash
            "0",                  // prevHash
            0,                    // height
            "genesis_dag_root_hash", // dagRootHash
            0,                    // timestamp
            nodeId,               // validatorId
            "genesis_signature",  // validatorSignature
            genesis_tx_ids        // transactionIds
        );
        std::unordered_map<std::string, std::shared_ptr<Transaction>> empty_confirmed_txs;
        finalityChain->addBlock(genesisBlock, empty_confirmed_txs);
        storageManager->saveBlock(genesisBlock);
        log("Genesis block created and saved.");
    } else {
        for (const auto& block : loadedBlocks) {
            // When loading blocks, we don't have the confirmed transactions readily available
            // This might need a more sophisticated loading mechanism or re-validation
            // For now, we'll pass an empty map, assuming transactions are loaded into DAG separately
            std::unordered_map<std::string, std::shared_ptr<Transaction>> empty_confirmed_txs;
            finalityChain->addBlock(block, empty_confirmed_txs);
        }
        log("Loaded " + std::to_string(loadedBlocks.size()) + " blocks into FinalityChain.");
    }

    // Simplified UTXO set initialization for testing
    // In a real system, this would be derived from the blockchain state
    // For now, we'll add a single UTXO for the node's initial balance
    if (utxoSet.empty()) {
        std::string genesisTxId = "genesis_utxo_tx";
        int outputIndex = 0;
        TransactionOutput genesisOutput(nodePublicKey, 1000.0);
        utxoSet[genesisTxId + ":" + std::to_string(outputIndex)] = genesisOutput;
        log("Node's initial UTXO set with 1000.0 for testing.");
    } else {
        log("Node's UTXO set loaded with " + std::to_string(utxoSet.size()) + " UTXOs.");
    }

    std::vector<std::shared_ptr<Transaction>> loadedTransactions = storageManager->loadAllTransactions();
    transactionDAG = std::make_shared<TransactionDAG>(*finalityChain);
    for (const auto& tx : loadedTransactions) {
        // In a real implementation, you'd check if the transaction is already in a block
        // For now, we add all loaded transactions to the DAG
        try {
            transactionDAG->addTransaction(tx); // UTXO set is now accessed via FinalityChain reference
        } catch (const TransactionError& e) {
            log("Error loading transaction into DAG: " + std::string(e.what()));
        } catch (const DAGError& e) {
            log("Error loading transaction into DAG: " + std::string(e.what()));
        }
    }
    log("Loaded " + std::to_string(transactionDAG->size()) + " pending transactions into DAG.");

    vmEngine = std::make_shared<VMEngine>();
    // Temporarily disable contract loading until StorageManager and VMEngine interfaces are fully aligned
    // std::unordered_map<std::string, std::shared_ptr<SmartContract>> loadedContracts = storageManager->loadAllContracts();
    // if (!loadedContracts.empty()) {
    //     vmEngine->loadDeployedContracts(loadedContracts);
    // }
    registerVmCallbacks();
    log("VMEngine initialized.");

    aiEngine = std::make_shared<AIEngine>();
    log("AIEngine initialized.");

    log("Node " + nodeId.substr(0, 8) + "... initialization complete.");
}

void Node::start() {
    log("Node " + nodeId.substr(0, 8) + "... started.");
}

// --- Reputation Management Logic ---
void Node::rewardNode(const std::string& nodeId, double points) {
    double currentRep = getNodeReputation(nodeId);
    currentRep = std::fmin(100.0, currentRep + points);
    reputationScores[nodeId] = currentRep;
    log("Node " + nodeId.substr(0, 8) + "... rewarded. New reputation: " + std::to_string(currentRep));
}

void Node::penalizeNode(const std::string& nodeId, double points) {
    double currentRep = getNodeReputation(nodeId);
    currentRep = std::fmax(-100.0, currentRep - points);
    reputationScores[nodeId] = currentRep;
    log("Node " + nodeId.substr(0, 8) + "... penalized. New reputation: " + std::to_string(currentRep));
}

std::pair<AIEngine::ProofOfComputation, double> Node::requestAiComputation(const std::string& data_input) {
    log("Requesting AI computation for data (length " + std::to_string(data_input.length()) + ")...");
    return aiEngine->run_inference_and_prove(data_input);
}

bool Node::verifyAiComputationProof(const std::string& data_input, double expected_score, const AIEngine::ProofOfComputation& proof) {
    log("Verifying AI computation proof for data (length " + std::to_string(data_input.length()) + ")...");
    return aiEngine->verify_proof(data_input, expected_score, proof);
}

double Node::getNodeReputation(const std::string& nodeId) const {
    auto it = reputationScores.find(nodeId);
    if (it != reputationScores.end()) {
        return it->second;
    }
    return 0.0; // Default reputation
}

// --- Private Node Logic ---
bool Node::processTransaction(std::shared_ptr<Transaction> tx) {
    if (!tx) {
        log("Attempted to process null transaction.");
        return false;
    }
    log("Processing transaction: " + tx->getId().substr(0, 8) + "...");

    // Validate the transaction using its own validate function
    try {
        tx->validate(finalityChain->getUtxoSet()); // Pass utxoSet for VALUE_TRANSFER validation
    } catch (const TransactionError& e) {
        log("Transaction " + tx->getId().substr(0, 8) + "... failed validation: " + std::string(e.what()));
        return false;
    }

    if (tx->getType() == TransactionType::AI_COMPUTATION_PROOF) {
        // The payload for AI_COMPUTATION_PROOF is expected to be JSON containing the ProofOfComputation details
        try {
            json proof_json = json::parse(tx->getPayload());
            AIEngine::ProofOfComputation proof;
            proof.data_hash = proof_json.at("data_hash").get<std::string>();
            proof.output_hash = proof_json.at("output_hash").get<std::string>();
            proof.signature = proof_json.at("signature").get<std::string>();
            proof.public_key = proof_json.at("public_key").get<std::string>();
            proof.computation_id = proof_json.at("computation_id").get<std::string>();

            double reported_score = proof_json.at("score").get<double>();
            std::string original_data_input = proof_json.at("original_data_input").get<std::string>();

            if (verifyAiComputationProof(original_data_input, reported_score, proof)) {
                ProvenWork proven_work = {
                    proof.computation_id,
                    reported_score,
                    tx->getCreatorPublicKey(),
                    std::chrono::system_clock::now()
                };
                finalityChain->getValidatorManager()->addProvenWork(proven_work);
                log("AI_COMPUTATION_PROOF successfully verified and added for validator " + tx->getCreatorPublicKey().substr(0,8) + "... Score: " + std::to_string(reported_score));
            } else {
                log("AI_COMPUTATION_PROOF verification failed for validator " + tx->getCreatorPublicKey().substr(0,8) + "...");
                return false;
            }
        } catch (const json::parse_error& e) {
            log("Error parsing AI_COMPUTATION_PROOF payload: " + std::string(e.what()));
            return false;
        } catch (const std::exception& e) {
            log("Error processing AI_COMPUTATION_PROOF: " + std::string(e.what()));
            return false;
        }
    }

    try {
        transactionDAG->addTransaction(tx);
        storageManager->saveTransaction(tx);
        log("Transaction " + tx->getId().substr(0, 8) + "... added to DAG.");
        return true;
    } catch (const DAGError& e) {
        log("Transaction " + tx->getId().substr(0, 8) + "... already in DAG or invalid structure: " + std::string(e.what()));
        return false;
    }
}

bool Node::broadcastTransaction(std::shared_ptr<Transaction> tx) {
    if (!tx) {
        log("Attempted to broadcast null transaction.");
        return false;
    }
    log("Broadcasting transaction: " + tx->getId().substr(0, 8) + "...");

    try {
        // Validate the transaction using its own validate function
        tx->validate(finalityChain->getUtxoSet());
        transactionDAG->addTransaction(tx);
        storageManager->saveTransaction(tx);
        log("Transaction " + tx->getId().substr(0, 8) + "... added to DAG and saved.");
        return true;
    } catch (const TransactionError& e) {
        log("Transaction " + tx->getId().substr(0, 8) + "... failed validation during broadcast: " + std::string(e.what()));
        return false;
    } catch (const DAGError& e) {
        log("Transaction " + tx->getId().substr(0, 8) + "... already in DAG or invalid structure: " + std::string(e.what()));
        return false;
    }
}

size_t Node::getDeployedContractsCount() const {
    return vmEngine->getAllDeployedContracts().size();
}

std::string Node::callContract(const std::string& contractId,
                               const std::string& senderId,
                               const std::string& methodName,
                               const std::string& paramsJson) {
    return vmEngine->executeContract(contractId, senderId, methodName, paramsJson);
}



void Node::updateUtxoSet(std::shared_ptr<Transaction> tx) {
    // This logic needs to be updated to handle the new transaction structure
    // For VALUE_TRANSFER transactions, update the UTXO set based on inputs and outputs
    if (tx->getType() == TransactionType::VALUE_TRANSFER) {
        try {
            json payload_json = json::parse(tx->getPayload());
            // Assuming TransactionInput and TransactionOutput have from_json overloads
            std::vector<TransactionInput> inputs = payload_json.at("inputs").get<std::vector<TransactionInput>>();
            std::vector<TransactionOutput> outputs = payload_json.at("outputs").get<std::vector<TransactionOutput>>();

            // Remove spent UTXOs
            for (const auto& input : inputs) {
                std::string utxo_id = input.transactionId + ":" + std::to_string(input.outputIndex);
                if (utxoSet.count(utxo_id)) {
                    utxoSet.erase(utxo_id);
                } else {
                    log("Warning: Attempted to spend non-existent UTXO: " + utxo_id);
                }
            }

            // Add new UTXOs (outputs)
            // Each output becomes a new UTXO, identified by transaction ID and output index
            for (size_t i = 0; i < outputs.size(); ++i) {
                std::string utxo_id = tx->getId() + ":" + std::to_string(i);
                utxoSet[utxo_id] = outputs[i];
            }
            log("UTXO set updated for VALUE_TRANSFER transaction: " + tx->getId().substr(0,8));
        } catch (const json::parse_error& e) {
            log("Error parsing VALUE_TRANSFER payload for UTXO update: " + std::string(e.what()));
        } catch (const std::exception& e) {
            log("Error updating UTXO set for VALUE_TRANSFER: " + std::string(e.what()));
        }
    }
    // Other transaction types do not directly affect the UTXO set in this simplified model
}

void Node::registerVmCallbacks() {
    // Callbacks are now handled internally by VMEngine via host functions during WASM instantiation.
    // The Node no longer directly sets these global callbacks on the VMEngine.
    log("VMEngine callbacks (host functions) are managed internally by VMEngine.");
}

// --- Public API ---

std::string Node::getChainTipHash() const {
    return finalityChain->getCurrentChainTipHash();
}

int Node::getChainTipHeight() const {
    return finalityChain->getCurrentHeight();
}

size_t Node::getPendingTransactionsCount() const {
    return transactionDAG->size(); // Use size() instead of getPendingTransactions().size()
}

std::shared_ptr<Block> Node::getBlockByHash(const std::string& blockHash) const {
    return finalityChain->getBlock(blockHash);
}

std::shared_ptr<Block> Node::mineBlock(const std::string& minterId) {
    std::string prevHash = getChainTipHash();
    int height = getChainTipHeight() + 1;

    // Get transactions to include in the block based on reputation scores
    std::vector<std::shared_ptr<Transaction>> txs = transactionDAG->getTransactionsToProcess(MAX_TRANSACTIONS_PER_BLOCK, reputationScores);

    // Calculate DAG root hash for the selected transactions
    std::string dagRoot = transactionDAG->calculateMerkleRoot(txs); // Assuming calculateMerkleRoot can take a subset of transactions

    // Create the new block
    std::shared_ptr<Block> newBlock = std::make_shared<Block>(
        prevHash, height, dagRoot, minterId, nodePrivateKeyPtr, txs);

    // Sign the block with the node's private key
    newBlock->sign(nodePrivateKeyPtr);

    // Add block to finality chain
    // Convert vector of shared_ptr<Transaction> to unordered_map<string, shared_ptr<Transaction>>
    std::unordered_map<std::string, std::shared_ptr<Transaction>> confirmedTxsMap;
    for (const auto& tx : txs) {
        confirmedTxsMap[tx->getId()] = tx;
    }
    finalityChain->addBlock(newBlock, confirmedTxsMap);
    storageManager->saveBlock(newBlock);

    // Remove mined transactions from the DAG
    for (const auto& tx : txs) {
        // transactionDAG->removeTransactions({tx->getId()}); // Assuming removeTransactions takes a vector of IDs
        updateUtxoSet(tx);
    }

    log("Mined new block at height " + std::to_string(height) + " with " + std::to_string(txs.size()) + " transactions.");
    return newBlock;
}

double Node::getAccountBalance(const std::string& accountId) const {
    double balance = 0.0;
    for (const auto& pair : utxoSet) {
        if (pair.second.recipientPublicKey == accountId) {
            balance += pair.second.amount;
        }
    }
    return balance;
}

void Node::deployContract(std::shared_ptr<SmartContract> contract, const std::vector<uint8_t>& wasmBytecode) {
    vmEngine->deployContract(contract, wasmBytecode);
    // storageManager->saveContract(contract); // StorageManager does not have saveContract anymore
    log("Deployed contract: " + contract->getContractId());
}

