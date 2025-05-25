#include "transaction.h" // يجب تضمين ملف الرأس الخاص بنا أولاً
#include <algorithm>     // لاستخدام std::sort و std::unique
#include <stdexcept>     // لاستخدام std::runtime_error

// --- تنفيذ الدوال المساعدة لـ TransactionOutput ---

// Constructor لإنشاء TransactionOutput
TransactionOutput::TransactionOutput(std::string txId, int outputIndex, std::string owner, double amount)
    : txId(std::move(txId)), outputIndex(outputIndex), owner(std::move(owner)), amount(amount) {
    // التحقق من القيم الأساسية (يمكن إضافة المزيد من التحقق هنا)
    if (this->txId.empty() || this->owner.empty() || this->amount <= 0 || this->outputIndex < 0) {
        throw TransactionError("Invalid TransactionOutput data provided.");
    }
}

// إنشاء معرف فريد لـ UTXO
std::string TransactionOutput::getId() const {
    // معرف UTXO يتكون من هاش المعاملة الأم ومؤشر الخرج
    return txId + ":" + std::to_string(outputIndex);
}

// تسلسل بيانات الخرج لأغراض حساب الهاش (للمعاملة الأم)
std::string TransactionOutput::serializeForTransactionHash() const {
    // نستخدم الـ owner والـ amount فقط لأنها الخصائص الثابتة للخرج
    // (txId و outputIndex يتم تحديدهما بعد إنشاء المعاملة).
    std::stringstream ss;
    ss << owner << ":" << std::fixed << std::setprecision(8) << amount;
    return ss.str();
}

// --- تنفيذ الدوال المساعدة لـ TransactionInput ---

// Constructor لإنشاء TransactionInput
TransactionInput::TransactionInput(std::string utxoId, std::string signature, std::string publicKey)
    : utxoId(std::move(utxoId)), signature(std::move(signature)), publicKey(std::move(publicKey)) {
    // التحقق من أن المدخلات ليست فارغة
    if (this->utxoId.empty() || this->signature.empty() || this->publicKey.empty()) {
        throw TransactionError("Invalid TransactionInput data provided (empty fields).");
    }
}

// تسلسل المدخل للتوقيع (ما يقوم المرسل بتوقيعه)
std::string TransactionInput::serializeForSigning(const std::string& newTxId) const {
    // يتم التوقيع على معرف الـ UTXO الذي يتم صرفه ومعرف المعاملة الجديدة التي ينتمي إليها المدخل.
    // هذا يربط التوقيع بالمعاملة المحددة ويمنع إعادة استخدام التوقيع في معاملة أخرى.
    return utxoId + ":" + newTxId;
}

// تسلسل المدخل لـ هاش المعاملة الجديدة
std::string TransactionInput::serializeForTransactionHash() const {
    // نضمّن الـ UTXO ID والتوقيع والمفتاح العام.
    // التوقيع والمفتاح العام مهمان لأنها خصائص فريدة لهذا المدخل بعد التوقيع.
    std::stringstream ss;
    ss << utxoId << ":" << signature << ":" << publicKey;
    return ss.str();
}


// --- تنفيذ دوال فئة Transaction ---

// Constructor لإنشاء معاملة جديدة (معاملة لم يتم توقيع مدخلاتها بالكامل بعد)
Transaction::Transaction(std::vector<TransactionInput> ins,
                         std::vector<TransactionOutput> outs,
                         std::vector<std::string> parents)
    : inputs(std::move(ins)), outputs(std::move(outs)), parentTxs(std::move(parents)) {
    
    // الحصول على الطابع الزمني الحالي
    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count();
    
    // حساب الـ TxId فوراً بعد إنشاء المعاملة
    createId();

    // بعد حساب الـ txId، نقوم بتحديث الـ utxoId لجميع المخرجات
    // هذا ضروري لأن معرف UTXO يعتمد على txId الخاص بالمعاملة الحالية.
    for (int i = 0; i < this->outputs.size(); ++i) {
        this->outputs[i].txId = this->txId;
        this->outputs[i].outputIndex = i; // نضمن أن يكون المؤشر صحيحاً
    }
}

// Constructor لاستعادة معاملة موجودة (من التخزين أو الشبكة)
Transaction::Transaction(std::vector<TransactionInput> ins,
                         std::vector<TransactionOutput> outs,
                         std::vector<std::string> parents,
                         std::int64_t ts,
                         std::string id)
    : inputs(std::move(ins)), outputs(std::move(outs)), parentTxs(std::move(parents)),
      timestamp(ts), txId(std::move(id)) {
    
    // التحقق من أن الـ txId ليس فارغاً (يجب أن يكون معروفاً عند الاستعادة)
    if (this->txId.empty()) {
        throw TransactionError("Restored transaction has empty ID.");
    }
    // يمكن هنا إضافة تحقق إضافي لضمان أن الـ ID المعطى يتطابق مع الهاش المحسوب
    // هذا يضمن سلامة البيانات المستعادة.
    // if (CryptoHelper::sha256(serializeForHash()) != this->txId) { ... }
}

// دالة داخلية لحساب هاش المعاملة (معرفها)
void Transaction::createId() {
    std::stringstream ss;

    // 1. تسلسل الطابع الزمني
    ss << timestamp;

    // 2. تسلسل مدخلات المعاملة
    // من المهم تسلسل المدخلات بترتيب ثابت لضمان نفس الهاش في كل مرة.
    // يمكننا فرزها بناءً على معرف الـ UTXO.
    std::vector<TransactionInput> sortedInputs = inputs;
    std::sort(sortedInputs.begin(), sortedInputs.end(), [](const TransactionInput& a, const TransactionInput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
    });
    for (const auto& input : sortedInputs) {
        ss << input.serializeForTransactionHash();
    }

    // 3. تسلسل مخرجات المعاملة
    // فرز المخرجات لضمان ترتيب ثابت.
    std::vector<TransactionOutput> sortedOutputs = outputs;
    std::sort(sortedOutputs.begin(), sortedOutputs.end(), [](const TransactionOutput& a, const TransactionOutput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
    });
    for (const auto& output : sortedOutputs) {
        ss << output.serializeForTransactionHash();
    }

    // 4. تسلسل المعاملات الأب في DAG (إن وجدت)
    std::vector<std::string> sortedParents = parentTxs;
    std::sort(sortedParents.begin(), sortedParents.end()); // فرز الهاشات الأب
    for (const auto& parent : sortedParents) {
        ss << parent;
    }
    
    // حساب الهاش النهائي وتخزينه في txId
    txId = CryptoHelper::sha256(ss.str());
}


// التحقق من صحة المعاملة
bool Transaction::validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const {
    // 1. التحقق من أن الـ TxId المحسوب يتطابق مع المخزن
    // هنا يجب أن نحسب الهاش بنفس الطريقة التي تم بها في createId
    // ونقارنه بالـ txId المخزن. هذا يضمن عدم التلاعب بالمعاملة.
    // بما أن createId هي دالة خاصة، سنقوم بعملية تسلسل مشابهة هنا.

    std::stringstream ssCheck;
    ssCheck << timestamp;

    std::vector<TransactionInput> sortedInputsCheck = inputs;
    std::sort(sortedInputsCheck.begin(), sortedInputsCheck.end(), [](const TransactionInput& a, const TransactionInput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
    });
    for (const auto& input : sortedInputsCheck) {
        ssCheck << input.serializeForTransactionHash();
    }

    std::vector<TransactionOutput> sortedOutputsCheck = outputs;
    std::sort(sortedOutputsCheck.begin(), sortedOutputsCheck.end(), [](const TransactionOutput& a, const TransactionOutput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
    });
    for (const auto& output : sortedOutputsCheck) {
        ssCheck << output.serializeForTransactionHash();
    }

    std::vector<std::string> sortedParentsCheck = parentTxs;
    std::sort(sortedParentsCheck.begin(), sortedParentsCheck.end());
    for (const auto& parent : sortedParentsCheck) {
        ssCheck << parent;
    }

    std::string calculatedTxId = CryptoHelper::sha256(ssCheck.str());
    if (calculatedTxId != txId) {
        throw TransactionError("Transaction hash mismatch. Data tampered or invalid.");
    }

    // 2. التحقق من عدم وجود مدخلات أو مخرجات فارغة
    if (inputs.empty() && outputs.empty()) {
        throw TransactionError("Transaction must have at least one input or one output.");
    }
    if (inputs.empty() && !outputs.empty()) {
        // إذا لم يكن هناك مدخلات (مثل المعاملة الأولى لتوليد العملة)
        // يجب أن يكون هناك خرج واحد فقط لتوليد العملة
        if (outputs.size() != 1) {
             throw TransactionError("Coinbase transaction must have exactly one output.");
        }
        // في نظام PoS، قد تكون هذه معاملة مكافأة للمدقق، تحتاج لقواعد خاصة.
        // يمكن التوسع هنا للتحقق من أن مصدر المكافأة صحيح.
        return true; // في حالة المعاملة الأولى (Coinbase)، لا يوجد مدخلات للتحقق منها.
    }
    if (outputs.empty()) {
        throw TransactionError("Transaction must have at least one output.");
    }


    // 3. التحقق من عدم صرف نفس الـ UTXO مرتين داخل نفس المعاملة (Double Spending within Tx)
    std::unordered_set<std::string> spentUtxosInThisTx;
    for (const auto& input : inputs) {
        if (spentUtxosInThisTx.count(input.utxoId)) {
            throw TransactionError("Transaction attempts to double-spend UTXO within itself: " + input.utxoId);
        }
        spentUtxosInThisTx.insert(input.utxoId);
    }

    // 4. التحقق من صحة المدخلات والتوقيعات والمبالغ
    double totalInputAmount = 0.0;
    for (const auto& input : inputs) {
        // البحث عن الـ UTXO المشار إليه في utxoSet
        auto it = utxoSet.find(input.utxoId);
        if (it == utxoSet.end()) {
            // إذا لم يتم العثور على الـ UTXO، فهذا يعني أنه تم صرفه بالفعل أو غير موجود
            throw TransactionError("Input UTXO not found or already spent: " + input.utxoId);
        }
        const TransactionOutput& referencedUtxo = it->second;

        // التحقق من أن المفتاح العام للمدخل يطابق مالك الـ UTXO المرجعي
        if (input.publicKey != referencedUtxo.owner) {
            throw TransactionError("Input public key does not match UTXO owner for UTXO: " + input.utxoId);
        }

        // بناء الرسالة التي تم توقيعها (نفس الرسالة التي تم استخدامها عند إنشاء التوقيع)
        std::string messageToVerify = input.serializeForSigning(txId);

        // التحقق من صحة التوقيع باستخدام المفتاح العام للمرسل
        std::vector<unsigned char> signatureBytes = hexToBytes(input.signature);
        if (!CryptoHelper::verifySignature(input.publicKey, signatureBytes, messageToVerify)) {
            throw TransactionError("Invalid signature for input UTXO: " + input.utxoId);
        }

        totalInputAmount += referencedUtxo.amount;
    }

    // 5. التحقق من مجموع مبالغ المخرجات
    double totalOutputAmount = 0.0;
    for (const auto& output : outputs) {
        if (output.amount <= 0) {
            throw TransactionError("Transaction output amount must be positive.");
        }
        totalOutputAmount += output.amount;
    }

    // 6. التحقق من توازن المبالغ (مجموع المدخلات >= مجموع المخرجات)
    // الفرق هو رسوم المعاملة، ويجب أن يكون غير سالب.
    if (totalInputAmount < totalOutputAmount) {
        throw TransactionError("Input amount " + std::to_string(totalInputAmount) + 
                               " is less than output amount " + std::to_string(totalOutputAmount));
    }
    // رسوم المعاملة هي totalInputAmount - totalOutputAmount

    // إذا تم اجتياز جميع التحققات، فالمعاملة صالحة
    return true;
}

// دالة مساعدة لإنشاء TransactionInput موقع
TransactionInput Transaction::createSignedInput(
    const std::string& utxoId,
    const CryptoHelper::ECKeyPtr& privateKey,
    const std::string& currentTxId // معرف المعاملة التي ينتمي إليها المدخل
) {
    // 1. الحصول على المفتاح العام من المفتاح الخاص
    std::string publicKeyHex = CryptoHelper::getPublicKeyHex(privateKey);

    // 2. بناء الرسالة التي سيتم توقيعها
    // الرسالة يجب أن تتضمن معرف الـ UTXO الذي يتم صرفه ومعرف المعاملة الجديدة
    std::string messageToSign = utxoId + ":" + currentTxId;

    // 3. توقيع الرسالة
    std::vector<unsigned char> signatureBytes = CryptoHelper::signData(privateKey, messageToSign);
    std::string signatureHex = bytesToHex(signatureBytes);

    // 4. إنشاء TransactionInput جديد وتعبئة بياناته
    return TransactionInput(utxoId, signatureHex, publicKeyHex);
}
