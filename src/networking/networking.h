#ifndef NETWORKING_H
#define NETWORKING_H

#include <string>
#include <vector>
#include <queue>          // For message queues
#include <mutex>          // For thread safety
#include <memory>         // For std::shared_ptr
#include <unordered_map>  // For managing connections to other nodes
#include <functional>     // For std::function (callback functions)
#include <stdexcept>      // For std::runtime_error

// Forward declarations to avoid circular dependencies
// A Networking class needs to know about Node, and Node needs to know about Networking.
// We'll pass shared_ptr<Node> to Networking's methods or constructor.
// Alternatively, Networking can be a separate layer that communicates via callbacks.
class Node; // Forward declaration of the Node class

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for Networking-specific errors.
 */
class NetworkingError : public std::runtime_error {
public:
    explicit NetworkingError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 1. Message Types (Basic)
// ---------------------------
enum class MessageType {
    TRANSACTION_BROADCAST, // Broadcast a new unconfirmed transaction
    BLOCK_BROADCAST,       // Broadcast a new confirmed block
    REQUEST_BLOCK,         // Request a specific block by hash or height
    REQUEST_TRANSACTION,   // Request a specific transaction by ID
    PEER_DISCOVERY,        // Discover new peers in the network
    ACKNOWLEDGE            // Acknowledge receipt of a message
    // ... add more message types as needed (e.g., voting messages, sync messages)
};

/**
 * Basic structure for a network message.
 * In a real system, this would be more complex (serialization, headers, checksums).
 */
struct NetworkMessage {
    MessageType type;
    std::string senderId; // ID of the node sending the message
    std::string payload;  // Serialized data (e.g., serialized Transaction or Block)
    std::string messageId; // Unique ID for this message (for ACKs, etc.)

    NetworkMessage(MessageType t, std::string sId, std::string p, std::string msgId = "")
        : type(t), senderId(std::move(sId)), payload(std::move(p)), messageId(std::move(msgId)) {
        if (messageId.empty()) {
            // Generate a simple unique ID for the message if not provided
            // In a real system, this would be a cryptographic hash or UUID
            messageId = CryptoHelper::sha256(senderId + payload + std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                std::chrono::high_resolution_clock::now().time_since_epoch()).count()));
        }
    }
};

// ---------------------------
// 2. Networking Interface (Abstract or Concrete)
// ---------------------------

/**
 * A basic simulation of a peer-to-peer networking layer for a blockchain node.
 * This class would handle sending and receiving messages between simulated nodes.
 * It uses a simple message queue for incoming messages and direct calls for sending.
 *
 * In a real-world scenario, this would involve actual sockets (TCP/UDP),
 * robust serialization/deserialization, NAT traversal, and peer discovery protocols.
 */
class Networking {
private:
    std::string nodeId; // The ID of the node this networking instance belongs to

    // Simulated network connections (direct pointers to other Networking instances)
    // In a real system, this would be socket connections.
    std::shared_ptr<std::unordered_map<std::string, std::shared_ptr<Networking>>> allNetworkInterfaces;

    // Incoming message queue for this node
    std::queue<NetworkMessage> incomingMessageQueue;
    mutable std::mutex queueMutex; // Mutex to protect the message queue

    // Callbacks to the Node for processing specific message types
    // These functions would be set by the Node instance.
    std::function<void(std::shared_ptr<Transaction>)> onReceiveTransactionCallback;
    std::function<void(std::shared_ptr<Block>)> onReceiveBlockCallback;
    // ... add callbacks for other message types (e.g., onBlockRequest, onTransactionRequest)

    /**
     * Internal method to process a single message from the queue.
     * This method would be called by the Node's tick() or a dedicated networking thread.
     */
    void processSingleMessage(const NetworkMessage& message);

public:
    // Constructor
    Networking(const std::string& id);

    /**
     * Initializes the networking layer by providing a shared reference to all
     * networking interfaces in the simulated network.
     * @param networkInterfaces A shared_ptr to a map of all networking instances.
     */
    void initialize(std::shared_ptr<std::unordered_map<std::string, std::shared_ptr<Networking>>> networkInterfaces);

    /**
     * Simulates sending a message to a specific peer.
     * @param recipientId The ID of the recipient node.
     * @param message The NetworkMessage to send.
     */
    void sendMessage(const std::string& recipientId, const NetworkMessage& message);

    /**
     * Simulates broadcasting a message to all connected peers (excluding self).
     * @param message The NetworkMessage to broadcast.
     */
    void broadcastMessage(const NetworkMessage& message);

    /**
     * Public method for other networking interfaces to add messages to this node's queue.
     * This simulates receiving a message over the network.
     * @param message The NetworkMessage to enqueue.
     */
    void enqueueMessage(const NetworkMessage& message);

    /**
     * Processes all pending messages in the incoming queue.
     * This method would typically be called by the Node's main loop (e.g., tick method).
     */
    void processIncomingMessages();

    /**
     * Sets the callback function for when a transaction message is received.
     * This allows the Networking layer to inform the Node layer about incoming transactions.
     * @param callback The function to call, typically Node::receiveTransaction.
     */
    void setOnReceiveTransactionCallback(std::function<void(std::shared_ptr<Transaction>)> callback) {
        onReceiveTransactionCallback = std::move(callback);
    }

    /**
     * Sets the callback function for when a block message is received.
     * This allows the Networking layer to inform the Node layer about incoming blocks.
     * @param callback The function to call, typically Node::receiveBlock.
     */
    void setOnReceiveBlockCallback(std::function<void<std::shared_ptr<Block>>> callback) {
        onReceiveBlockCallback = std::move(callback);
    }

    /**
     * Returns the number of messages currently in the incoming queue.
     */
    size_t getIncomingQueueSize() const;

    // Utility methods
    void clear(); // Clears internal state (for testing/reset)
};

#endif // NETWORKING_H