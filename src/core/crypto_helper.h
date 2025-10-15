#ifndef CRYPTO_HELPER_H
#define CRYPTO_HELPER_H

#include <string>
#include <cstddef> // For std::size_t
#include <vector>
#include <memory>    // For std::shared_ptr, std::unique_ptr
#include <stdexcept> // For std::runtime_error
#include <mutex>     // For std::once_flag, std::call_once
#include <sstream>   // For hex conversion
#include <iomanip>   // For hex conversion

// OpenSSL Includes
#include <openssl/ec.h>     // For EC_KEY, EC_POINT, EC_GROUP
#include <openssl/obj_mac.h> // For NID_secp256k1
#include <openssl/sha.h>    // For SHA256_DIGEST_LENGTH
#include <openssl/evp.h>    // For EVP_MD_CTX, EVP_sha256
#include <openssl/err.h>    // For error handling
#include <openssl/ecdsa.h>  // For ECDSA_SIG, ECDSA_do_sign, ECDSA_do_verify
#include <openssl/bio.h>    // For BIO_new_mem_buf, BIO_read, BIO_free
#include <openssl/pem.h>    // For PEM_read_bio_EC_PUBKEY, PEM_write_bio_EC_PUBKEY

/**
 * @brief Custom exception for cryptographic errors.
 */
class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @brief Utility class for cryptographic operations using OpenSSL.
 * Provides functionality for key generation, signing, verification, and hashing.
 * All public methods are static to allow direct calls without an object instance.
 */
class CryptoHelper {
public:
    // Typedef for a shared pointer to EC_KEY, with a custom deleter
    // The custom deleter ensures that OpenSSL EC_KEY objects are properly freed.
    using ECKeyPtr = std::shared_ptr<EC_KEY>;

private:
    // A flag to ensure OpenSSL initialization happens only once across the application.
    static std::once_flag cryptoInitFlag;

    // Private helper to initialize OpenSSL libraries.
    // This is called exactly once the first time any static CryptoHelper method is invoked.
    static void initializeOpenSSL();

    // Private helper to calculate SHA256 hash as bytes.
    static std::vector<unsigned char> sha256Bytes(const std::string& data);

public:
    // Constructors and destructors are deleted as this is a utility class with only static methods.
    CryptoHelper() = delete;
    ~CryptoHelper() = delete;

    /**
     * @brief Generates a new Elliptic Curve Cryptography (ECC) key pair using secp256k1 curve.
     * @return A shared_ptr to the generated EC_KEY structure containing both public and private keys.
     * @throws CryptoError if key generation fails.
     */
    static ECKeyPtr generateKeyPair();

    /**
     * @brief Extracts the public key in hexadecimal compressed format from an EC_KEY.
     * This format is suitable for representing addresses in a compact way.
     * @param key The EC_KEY shared pointer.
     * @return A string representing the compressed public key in hexadecimal format.
     * @throws CryptoError if extraction or conversion fails.
     */
    static std::string getPublicKeyHex(const ECKeyPtr& key);

    /**
     * @brief Converts a hexadecimal public key string back into an EC_KEY object.
     * This is useful for verifying signatures when only the hex public key is available.
     * @param publicKeyHex The hexadecimal string of the compressed public key.
     * @return A shared_ptr to the EC_KEY object.
     * @throws CryptoError if conversion or key parsing fails.
     */
    static ECKeyPtr publicKeyFromHex(const std::string& publicKeyHex);


    /**
     * @brief Signs a message using the provided private EC_KEY.
     * The message is first hashed internally using SHA-256 before signing.
     * @param privateKey The EC_KEY shared pointer containing the private key.
     * @param message The string message to be signed.
     * @return A vector of unsigned chars representing the DER-encoded signature.
     * @throws CryptoError if signing fails.
     */
    static std::vector<unsigned char> signData(const ECKeyPtr& privateKey, const std::string& message);

    /**
     * @brief Verifies an ECDSA signature against a message and a public key.
     * The public key is expected in hexadecimal compressed format. The message is hashed internally.
     * @param publicKeyHex The hexadecimal string of the compressed public key.
     * @param signature The vector of unsigned chars representing the DER-encoded signature.
     * @param message The original message string that was signed.
     * @return True if the signature is valid, false otherwise.
     * @throws CryptoError if verification setup or parsing fails.
     */
    static bool verifySignature(const std::string& publicKeyHex,
                                const std::vector<unsigned char>& signature,
                                const std::string& message);

    /**
     * @brief Computes the SHA-256 hash of a string and returns it as a hexadecimal string.
     * This is a common hashing function for data integrity and IDs.
     * @param data The string data to hash.
     * @return The SHA-256 hash as a hexadecimal string.
     * @throws CryptoError if hashing fails.
     */
    static std::string sha256(const std::string& data);

    static std::string signMessage(const ECKeyPtr& privateKey, const std::string& message);

    static bool verifySignature(const std::string& publicKeyHex, const std::string& signatureHex, const std::string& message);

    /**
     * @brief Converts a vector of bytes to its hexadecimal string representation.
     * Useful for displaying binary data or storing it in text formats.
     * @param bytes The vector of unsigned characters.
     * @return The hexadecimal string.
     */
    static std::string bytesToHex(const std::vector<unsigned char>& bytes);

    /**
     * @brief Converts a hexadecimal string to a vector of bytes.
     * Useful for parsing hexadecimal input back into binary data.
     * @param hexString The hexadecimal string.
     * @return The vector of unsigned characters.
     * @throws std::runtime_error if the hex string has an odd length or invalid characters.
     */
    static std::vector<unsigned char> hexToBytes(const std::string& hexString);
};

#endif // CRYPTO_HELPER_H