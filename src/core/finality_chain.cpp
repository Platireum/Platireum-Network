#include "crypto_helper.h"
#include <stdexcept>
#include <iostream> // For error logging to cerr

// Define the static member once_flag
std::once_flag CryptoHelper::cryptoInitFlag;

// Custom deleter for EC_KEY to ensure proper cleanup
namespace {
    struct ECKeyDeleter {
        void operator()(EC_KEY* key) const {
            if (key) EC_KEY_free(key);
        }
    };
} // end anonymous namespace

// Private helper to initialize OpenSSL libraries
void CryptoHelper::initializeOpenSSL() {
    // ERR_load_crypto_strings(); // Not strictly needed for basic EC operations, but good for debugging
    // OpenSSL_add_all_algorithms(); // Not strictly needed for basic EC operations
    // Seed PRNG if not already seeded (OpenSSL 1.1.0+ handles this automatically for most platforms)
}

// Private helper to calculate SHA256 hash as bytes
std::vector<unsigned char> CryptoHelper::sha256Bytes(const std::string& data) {
    std::call_once(cryptoInitFlag, initializeOpenSSL);

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    if (!SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash.data())) {
        throw CryptoError("Failed to compute SHA256 hash.");
    }
    return hash;
}

// Generates a new Elliptic Curve Cryptography (ECC) key pair using secp256k1 curve.
CryptoHelper::ECKeyPtr CryptoHelper::generateKeyPair() {
    std::call_once(cryptoInitFlag, initializeOpenSSL);

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        throw CryptoError("Failed to create EC_KEY: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    if (!EC_KEY_generate_key(ec_key)) {
        EC_KEY_free(ec_key);
        throw CryptoError("Failed to generate EC key pair: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    return ECKeyPtr(ec_key, ECKeyDeleter());
}

// Extracts the public key in hexadecimal compressed format from an EC_KEY.
std::string CryptoHelper::getPublicKeyHex(const ECKeyPtr& key) {
    if (!key) {
        throw CryptoError("Attempted to get public key from null EC_KEY pointer.");
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw CryptoError("Failed to create BIO for public key export.");
    }

    // Write public key in compressed form (POINT_CONVERSION_COMPRESSED)
    // PEM_write_bio_EC_PUBKEY writes in PEM format, which is not just raw hex.
    // We need to directly convert the EC_POINT to hex.
    const EC_GROUP* group = EC_KEY_get0_group(key.get());
    const EC_POINT* pub_point = EC_KEY_get0_public_key(key.get());
    if (!group || !pub_point) {
        BIO_free(bio);
        throw CryptoError("Failed to get EC group or public point.");
    }

    // Get the length of the public key in compressed form
    size_t len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    if (len == 0) {
        BIO_free(bio);
        throw CryptoError("Failed to get public key length.");
    }

    std::vector<unsigned char> pub_key_bytes(len);
    if (EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, pub_key_bytes.data(), len, NULL) == 0) {
        BIO_free(bio);
        throw CryptoError("Failed to convert public key to octet string.");
    }

    BIO_free(bio); // Free the BIO as it's no longer needed for this method
    return bytesToHex(pub_key_bytes);
}


// Converts a hexadecimal public key string back into an EC_KEY object.
CryptoHelper::ECKeyPtr CryptoHelper::publicKeyFromHex(const std::string& publicKeyHex) {
    std::call_once(cryptoInitFlag, initializeOpenSSL);

    std::vector<unsigned char> pub_key_bytes = hexToBytes(publicKeyHex);

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        throw CryptoError("Failed to create EC_KEY for public key import.");
    }

    const EC_POINT* pub_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
    if (!pub_point) {
        EC_KEY_free(ec_key);
        throw CryptoError("Failed to create EC_POINT for public key import.");
    }

    // Convert octet string to EC_POINT (public key)
    if (!EC_POINT_oct2point(EC_KEY_get0_group(ec_key), pub_point, pub_key_bytes.data(), pub_key_bytes.size(), NULL)) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        throw CryptoError("Failed to convert public key hex to EC_POINT: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        throw CryptoError("Failed to set public key on EC_KEY object: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    EC_POINT_free(pub_point); // Free the point after setting it

    return ECKeyPtr(ec_key, ECKeyDeleter());
}


// Signs a message using the provided private EC_KEY.
std::vector<unsigned char> CryptoHelper::signData(const ECKeyPtr& privateKey, const std::string& message) {
    if (!privateKey) {
        throw CryptoError("Attempted to sign with null private key.");
    }

    // Hash the message first
    std::vector<unsigned char> digest = sha256Bytes(message);

    unsigned int sig_len = 0;
    // ECDSA_size returns the maximum possible size of a DER-encoded signature
    // ECDSA_do_sign returns DER-encoded signature
    std::vector<unsigned char> signature(ECDSA_size(privateKey.get()));

    if (!ECDSA_sign(0, digest.data(), digest.size(), signature.data(), &sig_len, privateKey.get())) {
        throw CryptoError("Failed to sign data: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }

    signature.resize(sig_len); // Resize to actual signature length
    return signature;
}

// Verifies an ECDSA signature against a message and a public key.
bool CryptoHelper::verifySignature(const std::string& publicKeyHex,
                                   const std::vector<unsigned char>& signature,
                                   const std::string& message) {
    std::call_once(cryptoInitFlag, initializeOpenSSL);

    ECKeyPtr public_key = nullptr;
    try {
        public_key = publicKeyFromHex(publicKeyHex);
    } catch (const CryptoError& e) {
        std::cerr << "Error converting public key hex for verification: " << e.what() << std::endl;
        return false;
    }

    if (!public_key) {
        std::cerr << "Invalid public key after conversion for verification." << std::endl;
        return false;
    }

    // Hash the message first
    std::vector<unsigned char> digest = sha256Bytes(message);

    // ECDSA_verify returns 1 for success, 0 for failure, -1 for error
    int result = ECDSA_verify(0, digest.data(), digest.size(), signature.data(), signature.size(), public_key.get());
    if (result == 1) {
        return true;
    } else if (result == 0) {
        // Signature is invalid
        // ERR_print_errors_fp(stderr); // Uncomment for detailed OpenSSL error if verification fails
        return false;
    } else {
        // An error occurred during verification
        throw CryptoError("Error during signature verification: " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
}

// Computes the SHA-256 hash of a string and returns it as a hexadecimal string.
std::string CryptoHelper::sha256(const std::string& data) {
    std::vector<unsigned char> hash_bytes = sha256Bytes(data);
    return bytesToHex(hash_bytes);
}

// Converts a vector of bytes to its hexadecimal string representation.
std::string CryptoHelper::bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Converts a hexadecimal string to a vector of bytes.
std::vector<unsigned char> CryptoHelper::hexToBytes(const std::string& hexString) {
    if (hexString.length() % 2 != 0) {
        throw std::runtime_error("Hex string must have an even length.");
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hexString.length() / 2);
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception& e) {
            throw std::runtime_error("Invalid hexadecimal character in string: " + byteString + " (" + e.what() + ")");
        }
    }
    return bytes;
}