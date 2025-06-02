#ifndef NETWORKING_MESSAGES_H
#define NETWORKING_MESSAGES_H

#include <string>
#include <chrono> // For generating unique message IDs
#include "../../src/core/crypto_helper.h" // For SHA256 in message ID generation

// ---------------------------
// 1. Message Types
// ---------------------------
/**
 * Defines the various types of messages that can be exchanged between nodes.
 */
enum class MessageType {
    TRANSACTION_BROADCAST, // Broadcast a new unconfirmed transaction
    BLOCK_BROADCAST,       // Broadcast a new confirmed block
    REQUEST_BLOCK,         // Request a specific block by hash or height
    REQUEST_TRANSACTION,   // Request a specific transaction by ID
    PEER_DISCOVERY,        // Discover new peers in the network
    ACKNOWLEDGE            // Acknowledge receipt of a message
    // Add more message types as your network protocol evolves
    // e.g., VOTING_MESSAGE, CONSENSUS_ROUND_START, SYNC_REQUEST, etc.
};

// ---------------------------
// 2. Network Message Structure
// ---------------------------
/**
 * Basic structure for a network message.
 * This defines the common header information for all messages.
 * The 'payload' field will contain the actual data (e.g., serialized Transaction or Block).
 *
 * In a real-world system, this would typically involve:
 * - Versioning: To handle protocol upgrades.
 * - Checksums: For data integrity validation.
 * - More sophisticated routing information.
 */
struct NetworkMessage {
    MessageType type;
    std::string senderId;  // The ID (public key) of the node sending this message
    std::string payload;   // The actual data (e.g., serialized transaction, block)
    std::string messageId; // A unique identifier for this specific message instance

    /**
     * Constructor for NetworkMessage.
     * Generates a unique messageId if not provided.
     * The messageId helps in tracking messages, preventing duplicates, and for acknowledgments.
     */
    NetworkMessage(MessageType t, std::string sId, std::string p, std::string msgId = "")
        : type(t), senderId(std::move(sId)), payload(std::move(p)), messageId(std::move(msgId)) {
        if (this->messageId.empty()) {
            // Generate a simple unique ID for the message if not provided
            // This is a basic approach; a real system might use UUIDs or a more robust hash.
            // Using a combination of senderId, payload, and current time to ensure uniqueness.
            this->messageId = CryptoHelper::sha256(senderId + payload + std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                std::chrono::high_resolution_clock::now().time_since_epoch()).count()));
        }
    }

    // You might add serialization/deserialization methods here if messages become complex
    // std::string serialize() const;
    // static NetworkMessage deserialize(const std::string& data);
};

#endif // NETWORKING_MESSAGES_H