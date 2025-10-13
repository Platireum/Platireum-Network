#include "crypto_helper.h" // We must include our own header file first

// Initialize the static flag to ensure OpenSSL is initialized only once
std::once_flag CryptoHelper::cryptoInitFlag;

// --- Implementation of CryptoHelper helper functions ---

void CryptoHelper::initializeOpenSSL() {
    // This function initializes the OpenSSL libraries
    // OpenSSL_add_all_algorithms(): Adds support for all algorithms (encryption, hashing, signing).
    // ERR_load_crypto_strings()   : Loads error strings to facilitate debugging if an error occurs in OpenSSL.
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

CryptoHelper::ECKeyPtr CryptoHelper::generateKeyPair() {
    // We ensure OpenSSL is initialized only once upon the first call to this function
    std::call_once(cryptoInitFlag, initializeOpenSSL);
    
    // Create a new EC key structure using the secp256k1 curve (a common and secure curve for currencies like Bitcoin)
    // EC_KEY_free is the memory release function that std::shared_ptr uses automatically when the key is no longer needed
    ECKeyPtr key(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
    if (!key) {
        // If the structure creation fails, we throw a CryptoError exception
        throw CryptoError("Failed to create EC key structure");
    }
    
    // Generate the key pair (private and public)
    if (EC_KEY_generate_key(key.get()) != 1) {
        // If generation fails, we throw an exception
        throw CryptoError("Failed to generate key pair");
    }
    
    // Set the public key compression option (makes it smaller for storage and transport)
    EC_KEY_set_conv_form(key.get(), POINT_CONVERSION_COMPRESSED);
    
    return key; // We return the smart pointer to the key
}

std::string CryptoHelper::getPublicKeyHex(const ECKeyPtr& key) {
    const EC_POINT* pubKey = EC_KEY_get0_public_key(key.get());
    if (!pubKey) {
        throw CryptoError("Failed to get public key from EC_KEY");
    }
    
    const EC_GROUP* group = EC_KEY_get0_group(key.get());
    // BN_CTX is a context for big number libraries, used in some cryptographic operations.
    // It is automatically freed by std::unique_ptr
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx) {
        throw CryptoError("Failed to create BN context");
    }
    
    // Convert the public key from EC_POINT format to a compressed hexadecimal string
    // OPENSSL_free is the memory release function that std::unique_ptr uses for the hex string
    std::unique_ptr<char, decltype(&OPENSSL_free)> hexStr(
        EC_POINT_point2hex(group, pubKey, POINT_CONVERSION_COMPRESSED, ctx.get()),
        OPENSSL_free
    );
    
    if (!hexStr) {
        throw CryptoError("Failed to convert public key to hex string");
    }
    
    return std::string(hexStr.get()); // We return the string
}

std::vector<unsigned char> CryptoHelper::signData(const ECKeyPtr& privateKey, const std::string& message) {
    std::call_once(cryptoInitFlag, initializeOpenSSL); // We ensure initialization
    
    // First, we hash the message using SHA-256
    std::vector<unsigned char> msgHash = sha256Bytes(message);
    
    // Sign the hash using the private key.
    // ECDSA_SIG_free is the memory release function that std::unique_ptr uses for the signature.
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
        ECDSA_do_sign(msgHash.data(), msgHash.size(), privateKey.get()),
        ECDSA_SIG_free
    );
    
    if (!sig) {
        throw CryptoError("ECDSA signing failed");
    }
    
    // Convert the signature to DER (Distinguished Encoding Rules) format
    // This is a standard format for encoding signatures.
    unsigned char* der = nullptr;
    int derLen = i2d_ECDSA_SIG(sig.get(), &der); // i2d means "Internal to DER"
    
    if (derLen <= 0) {
        throw CryptoError("Failed to convert signature to DER format");
    }
    
    // We return the signature as a vector of bytes (unsigned chars)
    std::vector<unsigned char> signature(der, der + derLen);
    OPENSSL_free(der); // The memory allocated by i2d_ECDSA_SIG must be freed
    
    return signature;
}

bool CryptoHelper::verifySignature(const std::string& publicKeyHex,
                                     const std::vector<unsigned char>& signature,
                                     const std::string& message) {
    std::call_once(cryptoInitFlag, initializeOpenSSL); // We ensure initialization

    // 1. Reconstruct the public key from the hexadecimal string
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(
        EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free
    );
    if (!group) {
        throw CryptoError("Failed to create EC group for verification");
    }
    
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(EC_KEY_new(), EC_KEY_free);
    if (!key) {
        throw CryptoError("Failed to create EC_KEY for verification");
    }
    
    if (EC_KEY_set_group(key.get(), group.get()) != 1) {
        throw CryptoError("Failed to set EC group for key");
    }
    
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx) {
        throw CryptoError("Failed to create BN context for public key decoding");
    }
    
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(
        EC_POINT_new(group.get()), EC_POINT_free
    );
    // EC_POINT_hex2point: Converts the public key from a hex string to an EC_POINT structure
    if (!point || EC_POINT_hex2point(group.get(), publicKeyHex.c_str(), point.get(), ctx.get()) == nullptr) {
        throw CryptoError("Failed to decode public key from hex string");
    }
    
    if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
        throw CryptoError("Failed to set public key for verification");
    }
    
    // 2. Parse the signature from DER format
    const unsigned char* derSig = signature.data();
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
        d2i_ECDSA_SIG(nullptr, &derSig, signature.size()), // d2i means "DER to Internal"
        ECDSA_SIG_free
    );
    
    if (!sig) {
        throw CryptoError("Failed to parse signature from DER format");
    }
    
    // 3. Hash the original message and verify the signature
    std::vector<unsigned char> msgHash = sha256Bytes(message);
    // ECDSA_do_verify: The actual verification function
    int result = ECDSA_do_verify(msgHash.data(), msgHash.size(), sig.get(), key.get());
    
    if (result < 0) {
        // If the result is negative, there is an internal error in OpenSSL, not just an invalid signature
        throw CryptoError("Signature verification error (OpenSSL internal error)");
    }
    
    return result == 1; // 1 means a valid signature, 0 means an invalid signature
}

std::string CryptoHelper::sha256(const std::string& data) {
    // We return the byte hash and convert it to a hexadecimal string
    std::vector<unsigned char> hash = sha256Bytes(data);
    
    std::stringstream ss;
    for (unsigned char byte : hash) {
        // Format the bytes to be two hexadecimal digits (e.g., 0A, FF)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    
    return ss.str();
}

std::vector<unsigned char> CryptoHelper::sha256Bytes(const std::string& data) {
    // A vector to store the resulting hash, with the size of the SHA256 digest length
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    
    // EVP_MD_CTX: A context for Message Digest operations in OpenSSL
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdCtx(
        EVP_MD_CTX_new(), EVP_MD_CTX_free
    );
    
    if (!mdCtx) {
        throw CryptoError("Failed to create message digest context");
    }
    
    // Initialize the digest context using the SHA256 algorithm
    if (EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr) != 1) {
        throw CryptoError("Failed to initialize SHA256 digest");
    }
    
    // Update the digest with the input data
    if (EVP_DigestUpdate(mdCtx.get(), data.c_str(), data.size()) != 1) {
        throw CryptoError("Failed to update SHA256 digest with data");
    }
    
    unsigned int digestLen = 0;
    // Finalize the digest operation and get the output
    if (EVP_DigestFinal_ex(mdCtx.get(), hash.data(), &digestLen) != 1) {
        throw CryptoError("Failed to finalize SHA256 digest");
    }
    
    hash.resize(digestLen); // Adjust the vector size to match the actual hash length
    return hash;
}
