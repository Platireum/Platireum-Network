#include "networking.h"
#include "transaction.h" // We need the Transaction definition to deserialize it
#include "finality_chain.h" // We need the Block definition to deserialize it
#include <iostream>      // For logging
#include <algorithm>     // For std::find_if (if we need to search the peer list)

// --- Networking class function implementations ---

// Constructor
Networking::Networking(const std::string& id) : nodeId(id) {
    // Other initializations can be added here if necessary
}

// Initialize the network layer with references to other network interfaces
void Networking::initialize(std::shared_ptr<std::unordered_map<std::string, std::shared_ptr<Networking>>> networkInterfaces) {
    this->allNetworkInterfaces = networkInterfaces;
    // std::cout << "[Networking " << nodeId << "] Initialized with " << networkInterfaces->size() << " peers." << std::endl;
}

// Simulate sending a message to a specific peer
void Networking::sendMessage(const std::string& recipientId, const NetworkMessage& message) {
    if (!allNetworkInterfaces) {
        // std::cerr << "[Networking " << nodeId << "] Error: Network interfaces not initialized." << std::endl;
        return;
    }

    auto it = allNetworkInterfaces->find(recipientId);
    if (it != allNetworkInterfaces->end()) {
        // If the recipient exists, add the message to their queue
        it->second->enqueueMessage(message);
        // std::cout << "[Networking " << nodeId << "] Sent " << (int)message.type
        //           << " message to " << recipientId << std::endl;
    } else {
        // std::cerr << "[Networking " << nodeId << "] Warning: Recipient " << recipientId
        //           << " not found in network interfaces. Message not sent." << std::endl;
    }
}

// Simulate broadcasting a message to all connected peers (except the sender)
void Networking::broadcastMessage(const NetworkMessage& message) {
    if (!allNetworkInterfaces) {
        // std::cerr << "[Networking " << nodeId << "] Error: Network interfaces not initialized for broadcast." << std::endl;
        return;
    }

    // std::cout << "[Networking " << nodeId << "] Broadcasting " << (int)message.type
    //           << " message from " << message.senderId << std::endl;
              
    for (const auto& pair : *allNetworkInterfaces) {
        // Don't send the message back to the node that sent it (or the node this networking layer belongs to)
        if (pair.first != message.senderId) { // Use senderId from the message to avoid loops
            pair.second->enqueueMessage(message);
        }
    }
}

// Add a message to the incoming message queue
void Networking::enqueueMessage(const NetworkMessage& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    incomingMessageQueue.push(message);
    // std::cout << "[Networking " << nodeId << "] Enqueued message. Queue size: "
    //           << incomingMessageQueue.size() << std::endl;
}

// Process a single message from the queue
void Networking::processSingleMessage(const NetworkMessage& message) {
    // std::cout << "[Networking " << nodeId << "] Processing message type: " << (int)message.type
    //           << " from: " << message.senderId << std::endl;

    switch (message.type) {
        case MessageType::TRANSACTION_BROADCAST: {
            if (onReceiveTransactionCallback) {
                try {
                    // Deserialize the message payload into a Transaction object
                    std::shared_ptr<Transaction> tx = Transaction::deserialize(message.payload);
                    onReceiveTransactionCallback(tx);
                } catch (const std::exception& e) {
                    std::cerr << "[Networking " << nodeId << "] Error deserializing transaction: " << e.what() << std::endl;
                }
            } else {
                std::cerr << "[Networking " << nodeId << "] Warning: Transaction callback not set." << std::endl;
            }
            break;
        }
        case MessageType::BLOCK_BROADCAST: {
            if (onReceiveBlockCallback) {
                try {
                    // Deserialize the message payload into a Block object
                    std::shared_ptr<Block> block = Block::deserialize(message.payload);
                    onReceiveBlockCallback(block);
                } catch (const std::exception& e) {
                    std::cerr << "[Networking " << nodeId << "] Error deserializing block: " << e.what() << std::endl;
                }
            } else {
                std::cerr << "[Networking " << nodeId << "] Warning: Block callback not set." << std::endl;
            }
            break;
        }
        // Other cases for message types can be added here
        // case MessageType::REQUEST_BLOCK:
        // case MessageType::REQUEST_TRANSACTION:
        // case MessageType::PEER_DISCOVERY:
        // case MessageType::ACKNOWLEDGE:
        default: {
            // std::cout << "[Networking " << nodeId << "] Unknown or unhandled message type: " << (int)message.type << std::endl;
            break;
        }
    }
}

// Process all pending messages in the incoming queue
void Networking::processIncomingMessages() {
    std::lock_guard<std::mutex> lock(queueMutex); // Lock the queue during processing

    while (!incomingMessageQueue.empty()) {
        NetworkMessage message = incomingMessageQueue.front();
        incomingMessageQueue.pop();
        processSingleMessage(message);
    }
}

// Get the number of messages in the incoming queue
size_t Networking::getIncomingQueueSize() const {
    std::lock_guard<std::mutex> lock(queueMutex);
    return incomingMessageQueue.size();
}

// Clear the internal state
void Networking::clear() {
    std::lock_guard<std::mutex> lock(queueMutex);
    while (!incomingMessageQueue.empty()) {
        incomingMessageQueue.pop();
    }
    allNetworkInterfaces = nullptr; // Remove the network reference
    // std::cout << "[Networking " << nodeId << "] Cleared internal state." << std::endl;
}
