#include "transaction.h"
#include <algorithm>     // لاستخدام std::sort
#include <stdexcept>     // لاستخدام std::runtime_error
#include <iostream>      // For std::cerr in deserialize
#include <limits>        // For std::numeric_limits (not directly used here, but good practice for numeric types)

// Helper functions for deserialize to parse nested JSON objects without a library
namespace { // Anonymous namespace for local helper functions
    // Extracts string value from a key-value pair within a JSON segment
    std::string extract_string_value_local(const std::string& jsonSegment, const std::string& key) {
        size_t key_pos = jsonSegment.find("\"" + key + "\":");
        if (key_pos == std::string::npos) return std::string();
        size_t value_start = jsonSegment.find("\"", key_pos + key.length() + 3); // +3 for ":\"
        if (value_start == std::string::npos) return std::string();
        size_t value_end = jsonSegment.find("\"", value_start + 1);
        if (value_end == std::string::npos) return std::string();
        return jsonSegment.substr(value_start + 1, value_end - (value_start + 1));
    }

    // Extracts numeric (long long) value from a key-value pair within a JSON segment
    long long extract_numeric_value_local(const std::string& jsonSegment, const std::string& key) {
        size_t key_pos = jsonSegment.find("\"" + key + "\":");
        if (key_pos == std::string::npos) return 0;
        size_t value_start = key_pos + key.length() + 3; // +3 for ":"
        size_t value_end = jsonSegment.find_first_of(",}", value_start);
        if (value_end == std::string::npos) return 0;
        try {
            return std::stoll(jsonSegment.substr(value_start, value_end - value_start));
        } catch (const std::exception& e) {
            std::cerr << "Error parsing numeric value for key '" << key << "' from segment: " << e.what() << std::endl;
            return 0;
        }
    }
} // end anonymous namespace

// --- تنفيذ الدوال المساعدة لـ TransactionOutput ---

// Constructor لإنشاء TransactionOutput
TransactionOutput::TransactionOutput(std::string txId, int outputIndex, std::string owner, long long amount) // Changed double to long long
    : txId(std::move(txId)), outputIndex(outputIndex), owner(std::move(owner)), amount(amount) {
    if (this->txId.empty() || this->owner.empty() || this->amount <= 0 || this->outputIndex < 0) {
        throw TransactionError("Invalid TransactionOutput data provided.");
    }
}

// إنشاء معرف فريد لـ UTXO
std::string TransactionOutput::getId() const {
    return txId + ":" + std::to_string(outputIndex);
}

// تسلسل بيانات الخرج لأغراض حساب الهاش (للمعاملة الأم)
std::string TransactionOutput::serializeForTransactionHash() const {
    std::stringstream ss;
    ss << owner << ":" << amount; // Removed fixed and setprecision as long long is integer
    return ss.str();
}

// --- تنفيذ الدوال المساعدة لـ TransactionInput ---

// Constructor لإنشاء TransactionInput
TransactionInput::TransactionInput(std::string utxoId, std::string signature, std::string publicKey)
    : utxoId(std::move(utxoId)), signature(std::move(signature)), publicKey(std::move(publicKey)) {
    if (this->utxoId.empty() || this->signature.empty() || this->publicKey.empty()) {
        throw TransactionError("Invalid TransactionInput data provided (empty fields).");
    }
}

// تسلسل المدخل للتوقيع (ما يقوم المرسل بتوقيعه)
std::string TransactionInput::serializeForSigning(const std::string& newTxId) const {
    return utxoId + ":" + newTxId;
}

// تسلسل المدخل لـ هاش المعاملة الجديدة
std::string TransactionInput::serializeForTransactionHash() const {
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
    
    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count();
    
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
    
    if (this->txId.empty()) {
        throw TransactionError("Restored transaction has empty ID.");
    }
    // يمكن هنا إضافة تحقق إضافي لضمان أن الـ ID المعطى يتطابق مع الهاش المحسوب
    // (لضمان سلامة البيانات المستعادة)
    // if (CryptoHelper::sha256(serializeForHash()) != this->txId) { ... }
}

// دالة داخلية لحساب هاش المعاملة (معرفها)
void Transaction::createId() {
    std::stringstream ss;

    ss << timestamp;

    std::vector<TransactionInput> sortedInputs = inputs;
    std::sort(sortedInputs.begin(), sortedInputs.end(), [](const TransactionInput& a, const TransactionInput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
    });
    for (const auto& input : sortedInputs) {
        ss << input.serializeForTransactionHash();
    }

    std::vector<TransactionOutput> sortedOutputs = outputs;
    std::sort(sortedOutputs.begin(), sortedOutputs.end(), [](const TransactionOutput& a, const TransactionOutput& b) {
        return a.serializeForTransactionHash() < b.serializeForTransactionHash();
    });
    for (const auto& output : sortedOutputs) {
        ss << output.serializeForTransactionHash();
    }

    std::vector<std::string> sortedParents = parentTxs;
    std::sort(sortedParents.begin(), sortedParents.end());
    for (const auto& parent : sortedParents) {
        ss << parent;
    }
    
    txId = CryptoHelper::sha256(ss.str()); // Using static CryptoHelper::sha256
}


// التحقق من صحة المعاملة
bool Transaction::validate(const std::unordered_map<std::string, TransactionOutput>& utxoSet) const {
    // 1. التحقق من أن الـ TxId المحسوب يتطابق مع المخزن
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

    std::string calculatedTxId = CryptoHelper::sha256(ssCheck.str()); // Using static CryptoHelper::sha256
    if (calculatedTxId != txId) {
        throw TransactionError("Transaction hash mismatch. Data tampered or invalid.");
    }

    // 2. التحقق من عدم وجود مدخلات أو مخرجات فارغة (مع دعم coinbase)
    if (inputs.empty() && outputs.empty()) {
        throw TransactionError("Transaction must have at least one input or one output.");
    }
    if (inputs.empty()) { // Coinbase transaction (no inputs)
        if (outputs.size() != 1) {
            throw TransactionError("Coinbase transaction must have exactly one output.");
        }
        if (outputs[0].amount <= 0) {
            throw TransactionError("Coinbase output amount must be positive.");
        }
        return true; // No inputs to validate signatures/amounts for coinbase
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
    long long totalInputAmount = 0; // Changed double to long long
    for (const auto& input : inputs) {
        auto it = utxoSet.find(input.utxoId);
        if (it == utxoSet.end()) {
            // هذا يعني أن الـ UTXO غير موجود أو تم صرفه بالفعل في بلوك سابق.
            // يجب أن يتم التحقق من هذا في طبقة أعلى (TransactionDAG أو FinalityChain)
            // لتجنب الأخطاء عند التحقق من المعاملات الجديدة في الميمبول.
            // هنا، نرمي خطأ إذا لم يكن موجوداً في مجموعة UTXO التي تم تمريرها.
            throw TransactionError("Input UTXO not found in provided UTXO set: " + input.utxoId);
        }
        const TransactionOutput& referencedUtxo = it->second;

        if (input.publicKey != referencedUtxo.owner) {
            throw TransactionError("Input public key does not match UTXO owner for UTXO: " + input.utxoId);
        }

        std::string messageToVerify = input.serializeForSigning(txId);

        // استخدام دوال CryptoHelper الثابتة
        std::vector<unsigned char> signatureBytes = CryptoHelper::hexToBytes(input.signature); 
        if (!CryptoHelper::verifySignature(input.publicKey, signatureBytes, messageToVerify)) {
            throw TransactionError("Invalid signature for input UTXO: " + input.utxoId);
        }

        totalInputAmount += referencedUtxo.amount;
    }

    // 5. التحقق من مجموع مبالغ المخرجات
    long long totalOutputAmount = 0; // Changed double to long long
    for (const auto& output : outputs) {
        if (output.amount <= 0) {
            throw TransactionError("Transaction output amount must be positive.");
        }
        totalOutputAmount += output.amount;
    }

    // 6. التحقق من توازن المبالغ (مجموع المدخلات >= مجموع المخرجات)
    if (totalInputAmount < totalOutputAmount) {
        throw TransactionError("Input amount " + std::to_string(totalInputAmount) + 
                               " is less than output amount " + std::to_string(totalOutputAmount));
    }
    
    return true; // المعاملة صالحة
}

// دالة مساعدة لإنشاء TransactionInput موقع
TransactionInput Transaction::createSignedInput(
    const std::string& utxoId,
    const CryptoHelper::ECKeyPtr& privateKey,
    const std::string& currentTxId // معرف المعاملة التي ينتمي إليها المدخل
) {
    std::string publicKeyHex = CryptoHelper::getPublicKeyHex(privateKey); // استدعاء ثابت

    std::string messageToSign = utxoId + ":" + currentTxId;

    std::vector<unsigned char> signatureBytes = CryptoHelper::signData(privateKey, messageToSign); // استدعاء ثابت
    std::string signatureHex = CryptoHelper::bytesToHex(signatureBytes); // استدعاء ثابت

    return TransactionInput(utxoId, signatureHex, publicKeyHex);
}

std::string Transaction::toString() const {
    std::stringstream ss;
    ss << "TxId: " << txId.substr(0, std::min((size_t)12, txId.length())) << "...\n"
       << "Timestamp: " << timestamp << "\n"
       << "Parents: [";
    bool first_parent = true;
    for (const auto& p : parentTxs) {
        if (!first_parent) ss << ", ";
        ss << p.substr(0, std::min((size_t)8, p.length())) << "...";
        first_parent = false;
    }
    ss << "]\n"
       << "  Inputs (" << inputs.size() << "):\n";
    for (const auto& input : inputs) {
        ss << "    - UTXO: " << input.utxoId << ", Public Key: " << input.publicKey.substr(0, std::min((size_t)12, input.publicKey.length())) << "..., Signature: " << input.signature.substr(0, std::min((size_t)12, input.signature.length())) << "...\n";
    }
    ss << "  Outputs (" << outputs.size() << "):\n";
    for (const auto& output : outputs) {
        ss << "    - Owner: " << output.owner.substr(0, std::min((size_t)12, output.owner.length())) << "..., Amount: " << output.amount << "\n";
    }
    return ss.str();
}

std::string Transaction::serialize() const {
    // للتصغير والتبسيط، نستخدم تجميع السلاسل لـ JSON.
    // يوصى بشدة باستخدام مكتبة JSON مناسبة (مثل nlohmann/json) للتطبيقات الحقيقية.
    std::string inputs_json = "[";
    bool first_input = true;
    for (const auto& input : inputs) {
        if (!first_input) {
            inputs_json += ",";
        }
        inputs_json += "{\"utxoId\":\"" + input.utxoId + "\","
                       "\"signature\":\"" + input.signature + "\","
                       "\"publicKey\":\"" + input.publicKey + "\"}";
        first_input = false;
    }
    inputs_json += "]";

    std::string outputs_json = "[";
    bool first_output = true;
    for (const auto& output : outputs) {
        if (!first_output) {
            outputs_json += ",";
        }
        outputs_json += "{\"txId\":\"" + output.txId + "\","
                        "\"outputIndex\":" + std::to_string(output.outputIndex) + ","
                        "\"owner\":\"" + output.owner + "\","
                        "\"amount\":" + std::to_string(output.amount) + "}";
        first_output = false;
    }
    outputs_json += "]";

    std::string parents_json = "[";
    bool first_parent = true;
    for (const auto& parent : parentTxs) {
        if (!first_parent) {
            parents_json += ",";
        }
        parents_json += "\"" + parent + "\""; // هاش الأب هو سلسلة نصية
        first_parent = false;
    }
    parents_json += "]";

    std::stringstream ss;
    ss << "{"
       << "\"txId\":\"" << txId << "\","
       << "\"timestamp\":" << timestamp << ","
       << "\"inputs\":" << inputs_json << ","
       << "\"outputs\":" << outputs_json << ","
       << "\"parentTxs\":" << parents_json
       << "}";
    return ss.str();
}

std::shared_ptr<Transaction> Transaction::deserialize(const std::string& jsonString) {
    // هذا محلل JSON بدائي جداً.
    // في تطبيق حقيقي، استخدم مكتبة JSON قوية (مثل nlohmann/json).
    // هذا التنفيذ يفترض بنية JSON محددة وبسيطة وقد يفشل في حالة الإدخال غير الصحيح.

    std::string txId_val;
    std::int64_t timestamp_val = 0;
    std::vector<TransactionInput> inputs_val;
    std::vector<TransactionOutput> outputs_val;
    std::vector<std::string> parentTxs_val;

    // استخراج قيمة حقل "txId"
    txId_val = extract_string_value_local(jsonString, "txId");
    // استخراج قيمة حقل "timestamp"
    timestamp_val = extract_numeric_value_local(jsonString, "timestamp");

    // استخراج وتحليل مصفوفة المدخلات "inputs"
    size_t inputs_array_start = jsonString.find("\"inputs\":[");
    if (inputs_array_start != std::string::npos) {
        inputs_array_start += std::string("\"inputs\":").length(); // تقدم إلى بداية المصفوفة
        size_t inputs_array_end = jsonString.find("]", inputs_array_start);
        if (inputs_array_end != std::string::npos) {
            std::string inputs_segment = jsonString.substr(inputs_array_start, inputs_array_end - inputs_array_start);
            size_t current_pos = 0;
            // تكرار استخراج كائنات المدخلات الفردية
            while ((current_pos = inputs_segment.find("{", current_pos)) != std::string::npos) {
                size_t input_end = inputs_segment.find("}", current_pos);
                if (input_end != std::string::npos) {
                    std::string single_input_json = inputs_segment.substr(current_pos, input_end - current_pos + 1);
                    
                    std::string utxoId = extract_string_value_local(single_input_json, "utxoId");
                    std::string signature = extract_string_value_local(single_input_json, "signature");
                    std::string publicKey = extract_string_value_local(single_input_json, "publicKey");
                    
                    if (!utxoId.empty() && !signature.empty() && !publicKey.empty()) {
                        inputs_val.emplace_back(utxoId, signature, publicKey);
                    }
                    current_pos = input_end + 1;
                } else {
                    break; // JSON مكسور
                }
            }
        }
    }

    // استخراج وتحليل مصفوفة المخرجات "outputs"
    size_t outputs_array_start = jsonString.find("\"outputs\":[");
    if (outputs_array_start != std::string::npos) {
        outputs_array_start += std::string("\"outputs\":").length();
        size_t outputs_array_end = jsonString.find("]", outputs_array_start);
        if (outputs_array_end != std::string::npos) {
            std::string outputs_segment = jsonString.substr(outputs_array_start, outputs_array_end - outputs_array_start);
            size_t current_pos = 0;
            while ((current_pos = outputs_segment.find("{", current_pos)) != std::string::npos) {
                size_t output_end = outputs_segment.find("}", current_pos);
                if (output_end != std::string::npos) {
                    std::string single_output_json = outputs_segment.substr(current_pos, output_end - current_pos + 1);
                    
                    std::string txId_out = extract_string_value_local(single_output_json, "txId");
                    long long outputIndex_out = extract_numeric_value_local(single_output_json, "outputIndex");
                    std::string owner_out = extract_string_value_local(single_output_json, "owner");
                    long long amount_out = extract_numeric_value_local(single_output_json, "amount");

                    if (!owner_out.empty() && amount_out >= 0) { // Check minimal validity. Amount can be 0 for some specific cases (e.g. smart contracts with no value transfer)
                        outputs_val.emplace_back(txId_out, (int)outputIndex_out, owner_out, amount_out);
                    }
                    current_pos = output_end + 1;
                } else {
                    break;
                }
            }
        }
    }

    // استخراج وتحليل مصفوفة المعاملات الأب "parentTxs"
    size_t parents_array_start = jsonString.find("\"parentTxs\":[");
    if (parents_array_start != std::string::npos) {
        parents_array_start += std::string("\"parentTxs\":").length();
        size_t parents_array_end = jsonString.find("]", parents_array_start);
        if (parents_array_end != std::string::npos) {
            std::string parents_segment = jsonString.substr(parents_array_start, parents_array_end - parents_array_start);
            size_t current_pos = 0;
            while ((current_pos = parents_segment.find("\"", current_pos)) != std::string::npos) {
                size_t parent_end = parents_segment.find("\"", current_pos + 1);
                if (parent_end != std::string::npos) {
                    parentTxs_val.push_back(parents_segment.substr(current_pos + 1, parent_end - (current_pos + 1)));
                    current_pos = parent_end + 1;
                } else {
                    break;
                }
            }
        }
    }
    
    // إنشاء وإرجاع كائن المعاملة
    std::shared_ptr<Transaction> tx = std::make_shared<Transaction>(inputs_val, outputs_val, parentTxs_val, timestamp_val, txId_val);
    
    // اختياري: أعد حساب الهاش للتحقق من سلامة البيانات
    // بما أننا مررنا الـ txId إلى الكونستراكتور الثاني، فإننا نفترض أنه الهاش الصحيح.
    // إذا كنت ترغب في التحقق، يجب أن تقوم بذلك يدوياً هنا بعد إنشاء الكائن.
    // if (tx->getId() != txId_val) {
    //    std::cerr << "Warning: Deserialized transaction ID mismatch for txId: " << txId_val << std::endl;
    // }

    return tx;
}