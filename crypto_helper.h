#ifndef CRYPTO_HELPER_H
#define CRYPTO_HELPER_H

#include <string>
#include <vector>
#include <memory>       // For std::shared_ptr, std::unique_ptr
#include <mutex>        // For std::once_flag, std::call_once
#include <stdexcept>    // For std::runtime_error
#include <sstream>      // For std::stringstream
#include <iomanip>      // For std::setw, std::setfill

// OpenSSL headers
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// ---------------------------
// 0. Error Handling (أعيد تعريفها هنا لضمان توفرها حيث يتم استخدام CryptoHelper)
// ---------------------------
/**
 * Custom exception class for cryptographic errors
 */
class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {
        // Get additional OpenSSL error info
        char errBuf[256];
        unsigned long err = ERR_get_error();
        if (err) {
            ERR_error_string_n(err, errBuf, sizeof(errBuf));
            // يمكن طباعتها هنا أو يمكن تجميعها في رسالة الاستثناء نفسها
            // اخترت طباعتها مباشرة لتسهيل تتبع الأخطاء أثناء التطوير.
            std::cerr << "OpenSSL Error: " << errBuf << std::endl;
        }
    }
};

// ---------------------------
// Crypto Utilities 
// ---------------------------
/**
 * Handles all cryptographic operations using OpenSSL.
 * Provides a simpler, safer interface with resource management.
 */
class CryptoHelper {
public:
    // Smart pointer that auto-frees EC keys
    // يستخدم std::shared_ptr لأنه قد تحتاج أجزاء مختلفة من الكود
    // للاحتفاظ بنسخة من المفتاح العام (كمعرف للمحفظة مثلاً).
    using ECKeyPtr = std::shared_ptr<EC_KEY>;
    
    // Static flag for thread-safe OpenSSL initialization
    static std::once_flag cryptoInitFlag;

    /**
     * Initializes OpenSSL libraries once in a thread-safe manner.
     */
    static void initializeOpenSSL();

    /**
     * Generates a new elliptic curve key pair (secp256k1).
     * @return A shared_ptr to the generated EC_KEY.
     * @throws CryptoError if key generation fails.
     */
    static ECKeyPtr generateKeyPair();

    /**
     * Extracts the public key from an EC_KEY pointer as a hex string.
     * @param key A shared_ptr to the EC_KEY containing the key pair.
     * @return The public key as a hex-encoded string.
     * @throws CryptoError if extraction or conversion fails.
     */
    static std::string getPublicKeyHex(const ECKeyPtr& key);

    /**
     * Signs a message using the provided private key.
     * The message is first SHA-256 hashed, then signed using ECDSA.
     * @param privateKey A shared_ptr to the EC_KEY containing the private key.
     * @param message The string message to be signed.
     * @return A vector of unsigned chars representing the DER-encoded signature.
     * @throws CryptoError if signing fails.
     */
    static std::vector<unsigned char> signData(const ECKeyPtr& privateKey, const std::string& message);
    
    /**
     * Verifies an ECDSA signature against a message and a public key.
     * @param publicKeyHex The public key of the signer as a hex string.
     * @param signature The DER-encoded signature as a vector of unsigned chars.
     * @param message The original message that was signed.
     * @return True if the signature is valid, false otherwise.
     * @throws CryptoError if verification encounters an OpenSSL error.
     */
    static bool verifySignature(const std::string& publicKeyHex,
                                const std::vector<unsigned char>& signature,
                                const std::string& message);

    /**
     * Hashes data using SHA-256 and returns the hash as a hex string.
     * @param data The string data to hash.
     * @return The SHA-256 hash as a 64-character hex string.
     * @throws CryptoError if hashing fails.
     */
    static std::string sha256(const std::string& data);
    
    /**
     * Hashes data using SHA-256 and returns the hash as raw bytes.
     * @param data The string data to hash.
     * @return A vector of unsigned chars representing the SHA-256 hash.
     * @throws CryptoError if hashing fails.
     */
    static std::vector<unsigned char> sha256Bytes(const std::string& data);
};

// Helper functions for hex conversion (يمكن وضعها في ملف utility.h لاحقاً)
/**
 * Converts a vector of unsigned chars (bytes) to a hex string.
 */
inline std::string bytesToHex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

/**
 * Converts a hex string to a vector of unsigned chars (bytes).
 */
inline std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

#endif // CRYPTO_HELPER_H
