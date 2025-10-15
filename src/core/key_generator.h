#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include <string>
#include <memory>
#include "crypto_helper.h"

/**
 * @brief A utility class for generating cryptographic key pairs.
 * This class encapsulates the functionality to create new public/private key pairs
 * for nodes and accounts within the Platireum network.
 */
class KeyGenerator {
public:
    KeyGenerator() = default;

    /**
     * @brief Generates a new ECC key pair.
     * @return A pair of strings, where first is the public key (hex) and second is the private key (hex).
     */
    std::pair<std::string, std::string> generateKeyPair() const;

    /**
     * @brief Generates a new public key only (for addresses).
     * @return A string representing the public key in hexadecimal format.
     */
    std::string generatePublicKey() const;
};

#endif // KEY_GENERATOR_H

