#ifndef NODE_H
#define NODE_H

#include <string>
#include <vector>
#include <memory>         // For std::shared_ptr
#include <unordered_map>  // For local transaction pool
#include <unordered_set>  // For keeping track of known transactions/blocks
#include <queue>          // For message queue (basic simulation)
#include <mutex>          // For thread safety (if multi-threading is introduced later)
#include <stdexcept>      // For std::runtime_error
#include <thread>         // For simulating network/block proposal in a simple way

#include "crypto_helper.h"      // For cryptographic operations
#include "transaction.h"        // For Transaction definition
#include "transaction_dag.h"    // For TransactionDAG management
#include "finality_chain.h"     // For FinalityChain and Block definitions
#include "validator_manager.h"  // For ValidatorManager definition

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for Node-specific errors.
 */
class NodeError : public std::runtime_error {
public:
    explicit NodeError(const std::string& msg) : std::runtime_error(msg) {}
};

// Forward declarations to avoid circular includes if needed, but for now direct include is fine.
// class NetworkSimulator; // If we build a separate network simulation layer

/**
 * Represents a Node in the blockchain-DAG hybrid network.
 * It integrates all core components: cryptographic tools, transaction management,
 * DAG for unconfirmed transactions, Finality Chain for confirmed blocks,
 * and Validator Manager for Proof of Stake.
 */
class Node : public std::enable_shared_from_this<Node> { // Allows 'this' to be returned as shared_ptr
private:
    std::string nodeId; // Unique identifier for this node (e.g., its public key)
    CryptoHelper::ECKeyPtr privateKey; // The node's private key
    std::string publicKey;             // The node's public key (derived from privateKey)

    // Core components
    TransactionDAG dag;
    FinalityChain finalityChain;
    ValidatorManager validatorManager;

    // Simulation/Networking related (simplified for now)
    // In a real system, these would be sophisticated networking modules.
    std::shared_ptr<std::unordered_map<std::string, std::shared_ptr<Node>>> allNetworkNodes; // Pointer to all nodes in the simulated network
    std::mutex nodeMutex; // For protecting shared resources in a multi-threaded context

    // Track known transactions/blocks to avoid reprocessing (simplified)
    std::unordered_set<std::string> knownTransactions;
    std::unordered_set<std::string> knownBlocks;

    // Configuration parameters
    double minStakeAmount; // Minimum stake required to be a validator
    size_t maxTransactionsPerBlock; // Maximum transactions a block can contain

    // Utility for node operation
    void log(const std::string& message) const; // Simple logging utility

    /**
     * Attempts to propose a new block if this node is selected as validator.
     * This method simulates the block proposal logic.
     * @param currentTime The current simulated time (for consistent timestamps).
     */
    void tryProposeBlock(std::int64_t currentTime);

    /**
     * Processes an incoming transaction from the network.
     * @param tx The shared_ptr to the received transaction.
     */
    void processIncomingTransaction(std::shared_ptr<Transaction> tx);

    /**
     * Processes an incoming block from the network.
     * @param block The shared_ptr to the received block.
     */
    void processIncomingBlock(std::shared_ptr<Block> block);

    /**
     * Simulates broadcasting a transaction to other nodes.
     * @param tx The transaction to broadcast.
     */
    void broadcastTransaction(std::shared_ptr<Transaction> tx);

    /**
     * Simulates broadcasting a block to other nodes.
     * @param block The block to broadcast.
     */
    void broadcastBlock(std::shared_ptr<Block> block);

public:
    // Constructor
    Node(const std::string& initialId, double minStake = 100.0, size_t maxTxPerBlock = 10);

    /**
     * Initializes the node and potentially the genesis block of the finality chain.
     * @param isGenesisNode True if this node should create the genesis block.
     * @param networkNodes A shared_ptr to a map of all nodes in the simulated network.
     */
    void initialize(bool isGenesisNode, std::shared_ptr<std::unordered_map<std::string, std::shared_ptr<Node>>> networkNodes);

    // Getters
    const std::string& getNodeId() const { return nodeId; }
    const std::string& getPublicKey() const { return publicKey; }
    const FinalityChain& getFinalityChain() const { return finalityChain; }
    const TransactionDAG& getTransactionDAG() const { return dag; }
    const ValidatorManager& getValidatorManager() const { return validatorManager; }

    /**
     * Creates and signs a new transaction, then processes it locally and broadcasts it.
     * @param senderPrivateKey The private key of the sender.
     * @param recipientPublicKey The public key of the recipient.
     * @param amount The amount to send.
     * @param parentUtxos A vector of UTXOs to spend.
     * @return A shared_ptr to the created transaction.
     * @throws NodeError if transaction creation or signing fails.
     */
    std::shared_ptr<Transaction> createAndSendTransaction(
        const CryptoHelper::ECKeyPtr& senderPrivateKey,
        const std::string& recipientPublicKey,
        double amount,
        const std::vector<TransactionOutput>& parentUtxos // These UTXOs must exist in the sender's UTXO set
    );

    /**
     * Public interface for other nodes/network simulator to send transactions to this node.
     * @param tx A shared_ptr to the transaction received.
     */
    void receiveTransaction(std::shared_ptr<Transaction> tx);

    /**
     * Public interface for other nodes/network simulator to send blocks to this node.
     * @param block A shared_ptr to the block received.
     */
    void receiveBlock(std::shared_ptr<Block> block);

    /**
     * Simulates a single "tick" or step in the node's operation.
     * This might involve trying to propose a block, processing pending messages, etc.
     * @param currentTime The current simulated time.
     */
    void tick(std::int64_t currentTime);

    /**
     * Allows the node to register itself as a validator with a given stake.
     * @param stakeAmount The amount to stake.
     * @throws NodeError if stakeAmount is less than minStakeAmount.
     */
    void registerAsValidator(double stakeAmount);

    /**
     * Unregisters the node as a validator.
     */
    void unregisterAsValidator();
    
    // Debugging/Utility methods
    void printNodeStatus() const;
    void clear(); // Clears node state for testing/reset
};

#endif // NODE_H
