#ifndef NODE_H
#define NODE_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm> // Required for min/max/clamp if specific reputation logic is implemented

// Core components
#include "core/finality_chain.h" // For Block and FinalityChain
#include "core/transaction_dag.h" // For TransactionDAG
#include "core/transaction.h"    // For Transaction
#include "core/key_generator.h"  // For KeyGenerator
#include "storage/storage_manager.h" // For StorageManager

// Smart Contract components
#include "smart_contracts/vm_engine.h"
#include "smart_contracts/contract.h"

// Networking components (forward declarations if needed)
class NetworkManager;
class Peer;

/**
 * @brief Represents a single node in the blockchain network.
 * The Node class orchestrates interactions between various components:
 * TransactionDAG, FinalityChain, NetworkManager, StorageManager, and VMEngine.
 */
class Node {
private:
    std::string nodeId;
    std::string nodePublicKey;  // Public key associated with this node's identity
    std::string nodePrivateKey; // Private key for signing (for this node's operations)

    // Core Blockchain Components
    std::shared_ptr<FinalityChain> finalityChain;
    std::shared_ptr<TransactionDAG> transactionDAG;
    std::shared_ptr<KeyGenerator> keyGenerator;
    std::shared_ptr<StorageManager> storageManager;

    // Smart Contract Component
    std::shared_ptr<VMEngine> vmEngine;

    // Networking Component (conceptual - will be added later)
    // std::shared_ptr<NetworkManager> networkManager;

    // A simple UTXO set managed by the Node/FinalityChain (or derived from it)
    std::unordered_map<std::string, double> utxoSet; // Simplified: PublicKey -> Balance

    // --- Reputation System Integration (NEW) ---
    /**
     * @brief Stores the reputation score for other nodes.
     * Key: Node ID (std::string), Value: Reputation Score (double, e.g., 0.0 to 1.0).
     * Each node maintains its own view of other nodes' reputations.
     */
    std::unordered_map<std::string, double> reputationScores;

    // Private helper for internal logging
    void log(const std::string& message) const;

    // --- Private Node Logic ---
    // These functions encapsulate internal node operations.

    /**
     * @brief Processes a received transaction. Adds it to the DAG if valid.
     * @param tx The transaction to process.
     * @return True if processed successfully, false otherwise.
     */
    bool processTransaction(std::shared_ptr<Transaction> tx);

    /**
     * @brief Validates a transaction against UTXO set (simplified).
     * @param tx The transaction to validate.
     * @return True if valid, false otherwise.
     */
    bool validateTransaction(std::shared_ptr<Transaction> tx) const;

    /**
     * @brief Updates the local UTXO set based on a confirmed transaction/block.
     * @param tx The transaction that has been confirmed.
     * @param isCredit True if funds are being added, false if debited.
     */
    void updateUtxoSet(std::shared_ptr<Transaction> tx);

    /**
     * @brief Registers VM callbacks with the VMEngine.
     * This connects VM operations (like fund transfers) to Node's internal state.
     */
    void registerVmCallbacks();

    // --- Reputation Management Methods (NEW) ---

    /**
     * @brief Rewards a node by increasing its reputation score.
     * This is typically called upon successful, verified participation.
     * @param nodeId The ID of the node to reward.
     * @param points The amount of points to add to the score.
     */
    void rewardNode(const std::string& nodeId, double points);

    /**
     * @brief Penalizes a node by decreasing its reputation score.
     * This is typically called when a node exhibits malicious or incorrect behavior.
     * @param nodeId The ID of the node to penalize.
     * @param points The amount of points to subtract from the score.
     */
    void penalizeNode(const std::string& nodeId, double points);


public:
    /**
     * @brief Constructor for the Node.
     * @param id The unique ID for this node.
     * @param pubKey The public key of this node.
     * @param privKey The private key of this node.
     */
    Node(const std::string& id, const std::string& pubKey, const std::string& privKey);

    /**
     * @brief Initializes the node and its components.
     * This includes setting up storage, chains, and VM.
     */
    void initialize();

    /**
     * @brief Starts the node's main loop (e.g., listening for network activity, processing events).
     */
    void start();

    // --- Public API for Node Interaction (for ApiServer/CLI) ---

    /**
     * @brief Gets the unique ID of this node.
     * @return The node's ID.
     */
    const std::string& getNodeId() const { return nodeId; }

    /**
     * @brief Gets the public key of this node.
     * @return The node's public key.
     */
    const std::string& getNodePublicKey() const { return nodePublicKey; }

    /**
     * @brief Gets the hash of the current chain tip (latest block).
     * @return The hash of the tip block.
     */
    std::string getChainTipHash() const;

    /**
     * @brief Gets the height of the current chain tip.
     * @return The height of the tip block.
     */
    int getChainTipHeight() const;

    /**
     * @brief Gets the count of pending transactions in the DAG.
     * @return The number of pending transactions.
     */
    size_t getPendingTransactionsCount() const;

    /**
     * @brief Retrieves a block by its hash.
     * @param blockHash The hash of the block to retrieve.
     * @return A shared_ptr to the Block, or nullptr if not found.
     */
    std::shared_ptr<Block> getBlockByHash(const std::string& blockHash) const;

    /**
     * @brief Simulates mining a new block.
     * This is a simplified function for testing and will be replaced by actual consensus.
     * @param minterId The ID of the minter/validator.
     * @return A shared_ptr to the newly mined block, or nullptr on failure.
     */
    std::shared_ptr<Block> mineBlock(const std::string& minterId);

    /**
     * @brief Gets the balance of a specific account.
     * @param accountId The public key/ID of the account.
     * @return The balance of the account.
     */
    double getAccountBalance(const std::string& accountId) const;

    /**
     * @brief Get the count of UTXOs in the current set.
     * @return The number of UTXOs.
     */
    size_t getUtxoSetCount() const { return utxoSet.size(); }

    /**
     * @brief Broadcasts a transaction to the network (simulated).
     * This will add it to the local DAG for processing.
     * @param tx The transaction to broadcast.
     * @return True if the transaction was accepted for broadcasting, false otherwise.
     */
    bool broadcastTransaction(std::shared_ptr<Transaction> tx);

    /**
     * @brief Deploys a smart contract to the VM.
     * This function acts as a wrapper to VMEngine::deployContract.
     * @param contract The shared_ptr to the SmartContract to deploy.
     */
    void deployContract(std::shared_ptr<SmartContract> contract);

    /**
     * @brief Calls a method on a deployed smart contract.
     * This function acts as a wrapper to VMEngine::executeContract.
     * @param contractId The ID of the contract to call.
     * @param senderId The public key of the caller.
     * @param methodName The method to execute.
     * @param paramsJson JSON string of parameters for the method.
     * @return The result string from contract execution.
     */
    std::string callContract(const std::string& contractId,
        const std::string& senderId,
        const std::string& methodName,
        const std::string& paramsJson);

    /**
     * @brief Gets the number of deployed smart contracts.
     * @return The count of deployed contracts.
     */
    size_t getDeployedContractsCount() const;

    // --- Fund Transfer Callback (for VM) ---
    /**
     * @brief Handles fund transfers initiated by smart contracts.
     * This is designed to be the callback set in VMEngine::setOnTransferFundsCallback.
     * @param senderId The account sending funds.
     * @param recipientId The account receiving funds.
     * @param amount The amount to transfer.
     */
    void handleVmFundTransfer(const std::string& senderId, const std::string& recipientId, double amount);

    // --- Public Reputation Interface (NEW) ---

    /**
     * @brief Retrieves the current reputation score of a specific node.
     * If the node is not tracked, it returns a default (e.g., neutral) score.
     * @param nodeId The ID of the peer node whose reputation is sought.
     * @return The reputation score (double).
     */
    double getNodeReputation(const std::string& nodeId) const;
};

#endif // NODE_H
