#include "crypto_helper.h" // يجب تضمين ملف الرأس الخاص بنا أولاً

// تهيئة العلم الثابت لضمان تهيئة OpenSSL مرة واحدة فقط
std::once_flag CryptoHelper::cryptoInitFlag;

// --- تنفيذ الدوال المساعدة لـ CryptoHelper ---

void CryptoHelper::initializeOpenSSL() {
    // هذه الدالة تقوم بتهيئة مكتبات OpenSSL
    // OpenSSL_add_all_algorithms() : تضيف دعمًا لجميع الخوارزميات (التشفير، الهاش، التوقيع).
    // ERR_load_crypto_strings()    : تحمل سلاسل الأخطاء لتسهيل تصحيح الأخطاء إذا حدث خطأ ما في OpenSSL.
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

CryptoHelper::ECKeyPtr CryptoHelper::generateKeyPair() {
    // نضمن تهيئة OpenSSL مرة واحدة فقط عند أول استدعاء لهذه الدالة
    std::call_once(cryptoInitFlag, initializeOpenSSL);
    
    // إنشاء بنية مفتاح EC جديدة باستخدام منحنى secp256k1 (منحنى شائع وآمن لعملات مثل البيتكوين)
    // EC_KEY_free هو دالة تحرير الذاكرة التي يستخدمها std::shared_ptr تلقائياً عند عدم الحاجة للمفتاح
    ECKeyPtr key(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
    if (!key) {
        // إذا فشل إنشاء البنية، نطلق استثناء CryptoError
        throw CryptoError("Failed to create EC key structure");
    }
    
    // توليد زوج المفاتيح (الخاص والعام)
    if (EC_KEY_generate_key(key.get()) != 1) {
        // إذا فشل التوليد، نطلق استثناء
        throw CryptoError("Failed to generate key pair");
    }
    
    // تعيين خيار ضغط المفتاح العام (يجعله أصغر للتخزين والنقل)
    EC_KEY_set_conv_form(key.get(), POINT_CONVERSION_COMPRESSED);
    
    return key; // نُعيد المؤشر الذكي للمفتاح
}

std::string CryptoHelper::getPublicKeyHex(const ECKeyPtr& key) {
    const EC_POINT* pubKey = EC_KEY_get0_public_key(key.get());
    if (!pubKey) {
        throw CryptoError("Failed to get public key from EC_KEY");
    }
    
    const EC_GROUP* group = EC_KEY_get0_group(key.get());
    // BN_CTX هو سياق للمكتبات الكبيرة للأرقام، يُستخدم في بعض عمليات التشفير.
    // يتم تحريره تلقائياً بواسطة std::unique_ptr
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx) {
        throw CryptoError("Failed to create BN context");
    }
    
    // تحويل المفتاح العام من صيغة EC_POINT إلى سلسلة نصية سداسية عشرية مضغوطة
    // OPENSSL_free هو دالة تحرير الذاكرة التي يستخدمها std::unique_ptr للنص السداسي العشري
    std::unique_ptr<char, decltype(&OPENSSL_free)> hexStr(
        EC_POINT_point2hex(group, pubKey, POINT_CONVERSION_COMPRESSED, ctx.get()),
        OPENSSL_free
    );
    
    if (!hexStr) {
        throw CryptoError("Failed to convert public key to hex string");
    }
    
    return std::string(hexStr.get()); // نُعيد السلسلة النصية
}

std::vector<unsigned char> CryptoHelper::signData(const ECKeyPtr& privateKey, const std::string& message) {
    std::call_once(cryptoInitFlag, initializeOpenSSL); // نضمن التهيئة
    
    // أولاً، نقوم بتجزئة (hashing) الرسالة باستخدام SHA-256
    std::vector<unsigned char> msgHash = sha256Bytes(message);
    
    // التوقيع على التجزئة باستخدام المفتاح الخاص.
    // ECDSA_SIG_free هو دالة تحرير الذاكرة التي يستخدمها std::unique_ptr للتوقيع.
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
        ECDSA_do_sign(msgHash.data(), msgHash.size(), privateKey.get()),
        ECDSA_SIG_free
    );
    
    if (!sig) {
        throw CryptoError("ECDSA signing failed");
    }
    
    // تحويل التوقيع إلى صيغة DER (Distinguished Encoding Rules)
    // هذه صيغة قياسية لتشفير التوقيعات.
    unsigned char* der = nullptr;
    int derLen = i2d_ECDSA_SIG(sig.get(), &der); // i2d تعني "Internal to DER"
    
    if (derLen <= 0) {
        throw CryptoError("Failed to convert signature to DER format");
    }
    
    // نُعيد التوقيع كمتجه من البايتات (unsigned chars)
    std::vector<unsigned char> signature(der, der + derLen);
    OPENSSL_free(der); // يجب تحرير الذاكرة المخصصة بواسطة i2d_ECDSA_SIG
    
    return signature;
}

bool CryptoHelper::verifySignature(const std::string& publicKeyHex,
                                   const std::vector<unsigned char>& signature,
                                   const std::string& message) {
    std::call_once(cryptoInitFlag, initializeOpenSSL); // نضمن التهيئة

    // 1. إعادة بناء المفتاح العام من السلسلة السداسية العشرية
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
    // EC_POINT_hex2point : تحول المفتاح العام من سلسلة سداسية عشرية إلى بنية EC_POINT
    if (!point || EC_POINT_hex2point(group.get(), publicKeyHex.c_str(), point.get(), ctx.get()) == nullptr) {
        throw CryptoError("Failed to decode public key from hex string");
    }
    
    if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
        throw CryptoError("Failed to set public key for verification");
    }
    
    // 2. تحليل التوقيع من صيغة DER
    const unsigned char* derSig = signature.data();
    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
        d2i_ECDSA_SIG(nullptr, &derSig, signature.size()), // d2i تعني "DER to Internal"
        ECDSA_SIG_free
    );
    
    if (!sig) {
        throw CryptoError("Failed to parse signature from DER format");
    }
    
    // 3. تجزئة الرسالة الأصلية والتحقق من التوقيع
    std::vector<unsigned char> msgHash = sha256Bytes(message);
    // ECDSA_do_verify : دالة التحقق الفعلية
    int result = ECDSA_do_verify(msgHash.data(), msgHash.size(), sig.get(), key.get());
    
    if (result < 0) {
        // إذا كانت النتيجة سالبة، فهناك خطأ داخلي في OpenSSL وليس فقط توقيع غير صالح
        throw CryptoError("Signature verification error (OpenSSL internal error)");
    }
    
    return result == 1; // 1 تعني توقيع صالح، 0 تعني توقيع غير صالح
}

std::string CryptoHelper::sha256(const std::string& data) {
    // نُعيد تجزئة البايتات ونحولها إلى سلسلة سداسية عشرية
    std::vector<unsigned char> hash = sha256Bytes(data);
    
    std::stringstream ss;
    for (unsigned char byte : hash) {
        // تنسيق البايتات لتكون رقمين سداسيين عشريين (مثلاً 0A, FF)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    
    return ss.str();
}

std::vector<unsigned char> CryptoHelper::sha256Bytes(const std::string& data) {
    // متجه لتخزين الهاش الناتج، بحجم طول تجزئة SHA256
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    
    // EVP_MD_CTX : سياق لعمليات تجزئة الرسائل (Message Digest) في OpenSSL
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdCtx(
        EVP_MD_CTX_new(), EVP_MD_CTX_free
    );
    
    if (!mdCtx) {
        throw CryptoError("Failed to create message digest context");
    }
    
    // تهيئة سياق التجزئة باستخدام خوارزمية SHA256
    if (EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr) != 1) {
        throw CryptoError("Failed to initialize SHA256 digest");
    }
    
    // تحديث التجزئة بالبيانات المدخلة
    if (EVP_DigestUpdate(mdCtx.get(), data.c_str(), data.size()) != 1) {
        throw CryptoError("Failed to update SHA256 digest with data");
    }
    
    unsigned int digestLen = 0;
    // إنهاء عملية التجزئة والحصول على الناتج
    if (EVP_DigestFinal_ex(mdCtx.get(), hash.data(), &digestLen) != 1) {
        throw CryptoError("Failed to finalize SHA256 digest");
    }
    
    hash.resize(digestLen); // ضبط حجم المتجه ليتناسب مع طول الهاش الفعلي
    return hash;
}
