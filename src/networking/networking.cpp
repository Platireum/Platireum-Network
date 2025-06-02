#include "networking.h"
#include "transaction.h" // نحتاج لتعريف المعاملة لفك تسلسلها
#include "finality_chain.h" // نحتاج لتعريف Block لفك تسلسله
#include <iostream>      // للتسجيل (logging)
#include <algorithm>     // لـ std::find_if (إذا احتجنا للبحث في قائمة الأقران)

// --- تنفيذ دوال فئة Networking ---

// Constructor
Networking::Networking(const std::string& id) : nodeId(id) {
    // يمكن إضافة تهيئة أخرى هنا إذا لزم الأمر
}

// تهيئة طبقة الشبكة بمراجع إلى واجهات الشبكة الأخرى
void Networking::initialize(std::shared_ptr<std::unordered_map<std::string, std::shared_ptr<Networking>>> networkInterfaces) {
    this->allNetworkInterfaces = networkInterfaces;
    // std::cout << "[Networking " << nodeId << "] Initialized with " << networkInterfaces->size() << " peers." << std::endl;
}

// محاكاة إرسال رسالة إلى نظير محدد
void Networking::sendMessage(const std::string& recipientId, const NetworkMessage& message) {
    if (!allNetworkInterfaces) {
        // std::cerr << "[Networking " << nodeId << "] Error: Network interfaces not initialized." << std::endl;
        return;
    }

    auto it = allNetworkInterfaces->find(recipientId);
    if (it != allNetworkInterfaces->end()) {
        // إذا كان المستلم موجوداً، نُضيف الرسالة إلى قائمة انتظاره
        it->second->enqueueMessage(message);
        // std::cout << "[Networking " << nodeId << "] Sent " << (int)message.type 
        //           << " message to " << recipientId << std::endl;
    } else {
        // std::cerr << "[Networking " << nodeId << "] Warning: Recipient " << recipientId 
        //           << " not found in network interfaces. Message not sent." << std::endl;
    }
}

// محاكاة بث رسالة إلى جميع النظراء المتصلين (باستثناء المرسل)
void Networking::broadcastMessage(const NetworkMessage& message) {
    if (!allNetworkInterfaces) {
        // std::cerr << "[Networking " << nodeId << "] Error: Network interfaces not initialized for broadcast." << std::endl;
        return;
    }

    // std::cout << "[Networking " << nodeId << "] Broadcasting " << (int)message.type 
    //           << " message from " << message.senderId << std::endl;
              
    for (const auto& pair : *allNetworkInterfaces) {
        // لا ترسل الرسالة إلى العقدة التي أرسلتها (أو العقدة التي تنتمي إليها طبقة الشبكة هذه)
        if (pair.first != message.senderId) { // استخدم senderId من الرسالة لتجنب الحلقات
            pair.second->enqueueMessage(message);
        }
    }
}

// إضافة رسالة إلى قائمة انتظار الرسائل الواردة
void Networking::enqueueMessage(const NetworkMessage& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    incomingMessageQueue.push(message);
    // std::cout << "[Networking " << nodeId << "] Enqueued message. Queue size: " 
    //           << incomingMessageQueue.size() << std::endl;
}

// معالجة رسالة واحدة من قائمة الانتظار
void Networking::processSingleMessage(const NetworkMessage& message) {
    // std::cout << "[Networking " << nodeId << "] Processing message type: " << (int)message.type 
    //           << " from: " << message.senderId << std::endl;

    switch (message.type) {
        case MessageType::TRANSACTION_BROADCAST: {
            if (onReceiveTransactionCallback) {
                try {
                    // فك تسلسل (deserialize) حمولة الرسالة إلى كائن Transaction
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
                    // فك تسلسل (deserialize) حمولة الرسالة إلى كائن Block
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
        // يمكن إضافة حالات أخرى لأنواع الرسائل هنا
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

// معالجة جميع الرسائل المعلقة في قائمة الانتظار الواردة
void Networking::processIncomingMessages() {
    std::lock_guard<std::mutex> lock(queueMutex); // حماية قائمة الانتظار أثناء المعالجة

    while (!incomingMessageQueue.empty()) {
        NetworkMessage message = incomingMessageQueue.front();
        incomingMessageQueue.pop();
        processSingleMessage(message);
    }
}

// جلب عدد الرسائل في قائمة الانتظار الواردة
size_t Networking::getIncomingQueueSize() const {
    std::lock_guard<std::mutex> lock(queueMutex);
    return incomingMessageQueue.size();
}

// مسح الحالة الداخلية
void Networking::clear() {
    std::lock_guard<std::mutex> lock(queueMutex);
    while (!incomingMessageQueue.empty()) {
        incomingMessageQueue.pop();
    }
    allNetworkInterfaces = nullptr; // إزالة مرجع الشبكة
    // std::cout << "[Networking " << nodeId << "] Cleared internal state." << std::endl;
}