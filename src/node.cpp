#include "node.h"
#include <iostream>
#include <stdexcept>
#include <algorithm> // For std::remove_if
#include <chrono>    // For timestamp
#include <random>    // For std::mt19937 and std::uniform_int_distribution
#include <limits>    // For std::numeric_limits

// Global random device for generating node IDs, etc.
std::random_device rd_node_cpp;
std::mt19937 gen_node_cpp(rd_node_cpp());

// --- Helper for simple random ID generation ---
// Not cryptographically secure, just for simulation unique IDs
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

Node::Node(const std::string& id, const std::string& pubKey, const std::string& privKey)
    : nodeId(id), nodePublicKey(pubKey), nodePrivateKey(privKey) {
    
    log("Node " + nodeId.substr(0, 8) + "... created.");
}

void Node::log(const std::string& message) const {
    std::cout << "[Node " << nodeId.substr(0, 8) << "...] " << message << std::endl;
}

void Node::initialize() {
    log("Initializing node components...");

    // 1. Initialize KeyGenerator (if not already done globally/externally)
    keyGenerator = std::make_shared<KeyGenerator>();
    log("KeyGenerator initialized.");

    // 2. Initialize StorageManager
    storageManager = std::make_shared<StorageManager>("node_data_" + nodeId);
    storageManager->initialize();
    log("StorageManager initialized.");

    // 3. Initialize FinalityChain (Load existing blocks or create genesis)
    std::vector<std::shared_ptr<Block>> loadedBlocks = storageManager->loadAllBlocks();
    finalityChain = std::make_shared<FinalityChain>();
    if (loadedBlocks.empty()) {
        // Create a genesis block if no blocks are loaded
        log("No existing blocks found. Creating genesis block...");
        std::shared_ptr<Block> genesisBlock = std::make_shared<Block>(
            "genesis_block_hash", 0, "0", "genesis_dag_root_hash",
            0, nodeId, 0, "genesis_signature");
        finalityChain->addBlock(genesisBlock);
        storageManager->saveBlock(genesisBlock);
        log("Genesis block created and saved.");
    } else {
        // Load existing blocks into FinalityChain
        for (const auto& block : loadedBlocks) {
            finalityChain->addBlock(block);
        }
        log("Loaded " + std::to_string(loadedBlocks.size()) + " blocks into FinalityChain.");
    }
    
    // Initialize UTXO set from finality chain (simplified)
    // In a real system, UTXO set would be built by replaying confirmed transactions.
    // For now, we'll start with node's own balance from genesis, or load from storage
    // if a more persistent UTXO state is implemented later.
    // For testing, let's give the node some initial balance from genesis.
    if (!utxoSet.count(nodePublicKey)) {
        utxoSet[nodePublicKey] = 1000.0; // Initial balance for node for testing
        log("Node's initial balance set to 1000.0 for testing.");
    } else {
        log("Node's balance loaded: " + std::to_string(utxoSet[nodePublicKey]));
    }


    // 4. Initialize TransactionDAG (Load pending transactions or create empty)
    std::vector<std::shared_ptr<Transaction>> loadedTransactions = storageManager->loadAllTransactions();
    transactionDAG = std::make_shared<TransactionDAG>();
    for (const auto& tx : loadedTransactions) {
        if (!tx->getIsConfirmed()) { // Only load unconfirmed transactions into DAG
            transactionDAG->addTransaction(tx);
        }
    }
    log("Loaded " + std::to_string(transactionDAG->getPendingTransactions().size()) + " pending transactions into DAG.");


    // 5. Initialize VMEngine (Load existing contracts or create empty)
    vmEngine = std::make_shared<VMEngine>();
    std::unordered_map<std::string, std::shared_ptr<SmartContract>> loadedContracts = storageManager->loadAllContracts();
    if (!loadedContracts.empty()) {
        vmEngine->loadDeployedContracts(loadedContracts);
    }
    registerVmCallbacks(); // Crucial: Register callbacks after VM is initialized
    log("VMEngine initialized.");

    log("Node " + nodeId.substr(0, 8) + "... initialization complete.");
}

void Node::start() {
    log("Node " + nodeId.substr(0, 8) + "... started.");
    // In a real system, this would start network listeners, consensus algorithms, etc.
}

// --- Private Node Logic Implementations ---

bool Node::processTransaction(std::shared_ptr<Transaction> tx) {
    if (!tx) {
        log("Attempted to process null transaction.");
        return false;
    }
    log("Processing transaction: " + tx->getId().substr(0, 8) + "...");

    // 1. Basic Validation (e.g., format, signature - simplified)
    // In a real system, this would involve cryptographic checks.
    if (!validateTransaction(tx)) {
        log("Transaction " + tx->getId().substr(0, 8) + "... failed basic validation.");
        return false;
    }

    // 2. Add to DAG
    // The DAG handles checks for duplicates within itself
    bool addedToDag = transactionDAG->addTransaction(tx);
    if (addedToDag) {
        storageManager->saveTransaction(tx); // Persist pending transaction
        log("Transaction " + tx->getId().substr(0, 8) + "... added to DAG.");
        return true;
    } else {
        log("Transaction " + tx->getId().substr(0, 8) + "... already in DAG or invalid structure.");
        return false;
    }
}

bool Node::validateTransaction(std::shared_ptr<Transaction> tx) const {
    // Simplified validation: check if sender has enough balance for VALUE_TRANSFER
    if (tx->getType() == "VALUE_TRANSFER") {
        auto it = utxoSet.find(tx->getSender());
        if (it == utxoSet.end() || it->second < tx->getAmount()) {
            log("Validation failed: Insufficient funds for " + tx->getSender() + ". Needs " +
                std::to_string(tx->getAmount()) + ", has " + (it == utxoSet.end() ? "0" : std::to_string(it->second)));
            return false;
        }
    }
    // More complex validation (signature, valid fields, non-double-spend) goes here
    return true;
}

void Node::updateUtxoSet(std::shared_ptr<Transaction> tx) {
    if (tx->getType() == "VALUE_TRANSFER") {
        // Debit sender
        if (utxoSet.count(tx->getSender())) {
            utxoSet[tx->getSender()] -= tx->getAmount();
            if (utxoSet[tx->getSender()] < std::numeric_limits<double>::epsilon()) { // Check for near-zero
                utxoSet.erase(tx->getSender()); // Remove if balance is zero or negative
            }
        }
        // Credit recipient
        utxoSet[tx->getRecipient()] += tx->getAmount();
        log("UTXO updated for TX " + tx->getId().substr(0, 8) + "...: " +
            tx->getSender().substr(0,8) + " -> " + std::to_string(getAccountBalance(tx->getSender())) +
            ", " + tx->getRecipient().substr(0,8) + " -> " + std::to_string(getAccountBalance(tx->getRecipient())));
    }
    // For CONTRACT_DEPLOY and CONTRACT_CALL, fund transfers would typically happen
    // within the VM logic and be reflected via handleVmFundTransfer.
    // However, if contract deployment/call itself costs gas/fees, it would be deducted here.
    // For now, we only update for VALUE_TRANSFER directly.
}

void Node::registerVmCallbacks() {
    // Bind Node's handleVmFundTransfer to VMEngine's onTransferFundsCallback
    vmEngine->setOnTransferFundsCallback(
        [this](const std::string& sender, const std::string& recipient, double amount) {
            this->handleVmFundTransfer(sender, recipient, amount);
        });

    // Bind Node's getAccountBalance to VMEngine's onGetBalanceCallback
    vmEngine->setOnGetBalanceCallback(
        [this](const std::string& accountId) {
            return this->getAccountBalance(accountId);
        });
    log("VMEngine callbacks registered with Node.");
}

// --- Public API for Node Interaction Implementations (for ApiServer/CLI) ---

std::string Node::getChainTipHash() const {
    std::shared_ptr<Block> tip = finalityChain->getChainTip();
    return tip ? tip->getHash() : "N/A (No chain tip)";
}

int Node::getChainTipHeight() const {
    std::shared_ptr<Block> tip = finalityChain->getChainTip();
    return tip ? tip->getHeight() : -1;
}

size_t Node::getPendingTransactionsCount() const {
    return transactionDAG->getPendingTransactions().size();
}

std::shared_ptr<Block> Node::getBlockByHash(const std::string& blockHash) const {
    return finalityChain->getBlock(blockHash);
}

std::shared_ptr<Block> Node::mineBlock(const std::string& minterId) {
    log("Attempting to mine a new block...");
    
    // 1. Collect pending transactions from DAG
    std::vector<std::shared_ptr<Transaction>> txsToInclude;
    size_t count = 0;
    // Get a limited number of transactions for the block
    for (const auto& tx_pair : transactionDAG->getPendingTransactions()) {
        txsToInclude.push_back(tx_pair.second);
        count++;
        if (count >= 10) break; // Limit block size for simulation
    }

    // 2. Create Block (simplified hash, prev hash, etc.)
    std::string newBlockHash = generateRandomId(64);
    int newBlockHeight = getChainTipHeight() + 1;
    std::string prevBlockHash = getChainTipHash();
    long long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    
    // For simplicity, root hash is just a hash of included txs (in a real system, it's Merkle root)
    std::string dagRootHash = "dag_root_hash_" + std::to_string(timestamp); 

    std::shared_ptr<Block> newBlock = std::make_shared<Block>(
        newBlockHash, newBlockHeight, prevBlockHash, dagRootHash,
        0, minterId, timestamp, "dummy_signature"); // Nonce and signature are dummy

    // Add transactions to the block
    for (const auto& tx : txsToInclude) {
        newBlock->addTransaction(tx);
    }
    
    // 3. Validate and Add to FinalityChain
    // In a real system, this would involve Proof-of-Work/Stake verification.
    finalityChain->addBlock(newBlock);
    
    // 4. Update state based on confirmed transactions in the new block
    for (const auto& tx : newBlock->getTransactions()) {
        updateUtxoSet(tx);
        transactionDAG->markTransactionAsConfirmed(tx->getId());
        storageManager->saveTransaction(tx); // Update confirmed status in storage
    }
    
    // 5. Persist the new block
    storageManager->saveBlock(newBlock);

    log("Mined block " + newBlock->getHash().substr(0, 8) + "... at height " + std::to_string(newBlock->getHeight()) +
        " with " + std::to_string(newBlock->getTransactions().size()) + " transactions.");
    return newBlock;
}

double Node::getAccountBalance(const std::string& accountId) const {
    auto it = utxoSet.find(accountId);
    if (it != utxoSet.end()) {
        return it->second;
    }
    return 0.0; // Account not found or has no balance
}

bool Node::broadcastTransaction(std::shared_ptr<Transaction> tx) {
    // In a real network, this would send the transaction to connected peers.
    // For now, it just processes it locally.
    log("Received transaction for broadcast: " + tx->getId().substr(0, 8) + "...");
    return processTransaction(tx);
}

void Node::deployContract(std::shared_ptr<SmartContract> contract) {
    log("Request to deploy contract: " + contract->getId().substr(0, 8) + "...");
    try {
        vmEngine->deployContract(contract);
        storageManager->saveContract(contract); // Persist the deployed contract
        log("Contract " + contract->getId().substr(0, 8) + "... deployed successfully.");
    } catch (const std::runtime_error& e) {
        log("Error deploying contract: " + std::string(e.what()));
        throw; // Re-throw to be caught by ApiServer/CLI
    }
}

std::string Node::callContract(const std::string& contractId,
                               const std::string& senderId,
                               const std::string& methodName,
                               const std::string& paramsJson) {
    log("Request to call contract " + contractId.substr(0, 8) + "... method: " + methodName + " from " + senderId.substr(0, 8) + "...");
    try {
        std::string result = vmEngine->executeContract(contractId, senderId, methodName, paramsJson);
        // After contract execution, persist the updated state of the contract if it changed.
        std::shared_ptr<SmartContract> updatedContract = vmEngine->getContract(contractId);
        if (updatedContract) {
            storageManager->saveContract(updatedContract); // Overwrite with updated state
        }
        log("Contract call result: " + result);
        return result;
    } catch (const std::runtime_error& e) {
        log("Error calling contract: " + std::string(e.what()));
        throw; // Re-throw to be caught by ApiServer/CLI
    }
}

size_t Node::getDeployedContractsCount() const {
    return vmEngine->getAllDeployedContracts().size();
}

void Node::handleVmFundTransfer(const std::string& senderId, const std::string& recipientId, double amount) {
    log("VM requested fund transfer: " + std::to_string(amount) + " from " + senderId.substr(0, 8) + "... to " + recipientId.substr(0, 8) + "...");
    
    // This is a critical point: how does a VM-initiated transfer affect the actual blockchain state?
    // Option 1 (Simplified for now): Directly update internal UTXO map.
    // This is NOT how real blockchains work for contract-initiated transfers.
    // Real blockchains would create an *internal transaction* or log an *event*
    // that gets processed and affects the UTXO set during block finalization.

    if (getAccountBalance(senderId) < amount) {
        log("VM fund transfer failed: Insufficient balance for " + senderId.substr(0, 8) + "...");
        // In a real VM, this would consume gas and revert the contract state.
        return; 
    }

    // Perform the transfer
    utxoSet[senderId] -= amount;
    if (utxoSet[senderId] < std::numeric_limits<double>::epsilon()) { // Handle near-zero
        utxoSet.erase(senderId);
    }
    utxoSet[recipientId] += amount;

    log("VM fund transfer successful. New balances: " + senderId.substr(0, 8) + " = " + std::to_string(getAccountBalance(senderId)) +
        ", " + recipientId.substr(0, 8) + " = " + std::to_string(getAccountBalance(recipientId)));
    
    // In a production blockchain, this would typically queue an internal transaction or event
    // that would then be included in a block and affect the global state.
    // For this simulation, direct UTXO update is acceptable for the VM callback.
}