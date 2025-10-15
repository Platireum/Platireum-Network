#include "key_generator.h"
#include "crypto_helper.h"

std::pair<std::string, std::string> KeyGenerator::generateKeyPair() const {
    CryptoHelper::ECKeyPtr key_pair = CryptoHelper::generateKeyPair();
    std::string public_key = CryptoHelper::getPublicKeyHex(key_pair);
    // In a real system, you would serialize the private key securely.
    // For simulation, we'll just return a placeholder or a derived value.
    // For now, let's just return the public key as the private key for simplicity in simulation.
    // This is NOT secure and should NOT be used in production.
    return {public_key, public_key}; // Placeholder: private key is public key for simplicity
}

std::string KeyGenerator::generatePublicKey() const {
    CryptoHelper::ECKeyPtr key_pair = CryptoHelper::generateKeyPair();
    return CryptoHelper::getPublicKeyHex(key_pair);
}

