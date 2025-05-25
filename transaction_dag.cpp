#include "transaction_dag.h" // يجب تضمين ملف الرأس الخاص بنا أولاً
#include <iostream>          // للاستخدام في دوال الطباعة لتصحيح الأخطاء

// --- تنفيذ دوال فئة TransactionDAG ---

// Constructor
TransactionDAG::TransactionDAG() {
    // يمكن هنا تهيئة أي هياكل بيانات إذا لزم الأمر، لكن بالنسبة لـ unordered_map و unordered_set
    // يتم تهيئتها تلقائياً لتكون فارغة.
}

// دالة مساعدة لتحديث المعاملات "الطرفية" (tips)
void TransactionDAG::updateTips(const std::string& newTxId, const std::vector<std::string>& parentTxIds) {
    // أولاً: إذا كانت المعاملة الجديدة هي أول معاملة في الـ DAG، تصبح هي الـ tip الوحيد
    if (transactions.size() == 1 && parentTxIds.empty()) {
        tips.insert(newTxId);
        return;
    }

    // ثانياً: أي من الآباء الذين تم الإشارة إليهم من قبل المعاملة الجديدة لم يعد "tip"
    for (const std::string& parentId : parentTxIds) {
        tips.erase(parentId); // إزالة الـ parentId من مجموعة الـ tips
    }

    // ثالثاً: المعاملة الجديدة نفسها تصبح "tip" لأنها لم يتم الإشارة إليها كـ "أب" بعد
    tips.insert(newTxId);
}

// دالة مساعدة للتحقق من وجود المعاملات الأب
void TransactionDAG::validateParentExistence(const std::vector<std::string>& parentTxIds) const {
    if (parentTxIds.empty() && !transactions.empty()) {
        // إذا كان هناك معاملات في الـ DAG، فإن أي معاملة جديدة يجب أن تشير إلى آباء.
        // المعاملة الأولى فقط يمكن أن تكون بدون آباء.
        throw DAGError("New transaction must reference parent transactions in a non-empty DAG.");
    }
    
    for (const std::string& parentId : parentTxIds) {
        if (transactions.find(parentId) == transactions.end()) {
            // إذا لم يتم العثور على أي من الآباء في الـ DAG
            throw DAGError("Parent transaction not found in DAG: " + parentId);
        }
    }
}

// إضافة معاملة جديدة إلى الـ DAG
void TransactionDAG::addTransaction(std::shared_ptr<Transaction> tx) {
    if (!tx) {
        throw DAGError("Attempted to add a null transaction to DAG.");
    }
    const std::string& txId = tx->getId();

    // 1. التحقق مما إذا كانت المعاملة موجودة بالفعل
    if (transactions.count(txId)) {
        throw DAGError("Transaction already exists in DAG: " + txId);
    }

    // 2. التحقق من صحة المعاملة نفسها (باستخدام دالة validate الخاصة بالمعاملة)
    // ملاحظة: دالة validate تتطلب UTXO set. سنحتاج إلى تمرير UTXO set فارغ
    // مؤقتًا هنا، أو دمج logic UTXO set في فئة أكبر تجمع DAG و UTXO.
    // في بيئة حقيقية، المعاملة لن تصل إلى DAG إلا بعد التحقق من صحتها مقابل
    // UTXO set الحالي.
    // لأغراض التطوير الآن، لن نمرر UTXO set فعلي هنا.
    // هذا الجزء سيتطلب تعديلاً لاحقاً عندما ندمج UTXO set العالمي.
    // if (!tx->validate(current_utxo_set)) {
    //     throw TransactionError("Transaction validation failed before adding to DAG.");
    // }

    // 3. التحقق من وجود المعاملات الأب في الـ DAG
    const std::vector<std::string>& parentTxIds = tx->getParents();
    validateParentExistence(parentTxIds);

    // 4. إضافة المعاملة إلى الخريطة الرئيسية
    transactions[txId] = tx;

    // 5. تحديث خرائط الأبناء والآباء
    for (const std::string& parentId : parentTxIds) {
        childrenMap[parentId].push_back(txId);
        parentMap[txId].push_back(parentId);
    }

    // 6. تحديث قائمة المعاملات الطرفية (tips)
    updateTips(txId, parentTxIds);

    // يمكنك إضافة رسالة طباعة للمساعدة في تصحيح الأخطاء
    // std::cout << "Transaction " << txId.substr(0, 8) << "... added to DAG. Tips count: " << tips.size() << std::endl;
}

// استرجاع معاملة من الـ DAG
std::shared_ptr<Transaction> TransactionDAG::getTransaction(const std::string& txId) const {
    auto it = transactions.find(txId);
    if (it != transactions.end()) {
        return it->second;
    }
    return nullptr; // نُعيد مؤشر فارغ إذا لم يتم العثور على المعاملة
}

// إزالة مجموعة من المعاملات من الـ DAG (بعد تضمينها في بلوك)
void TransactionDAG::removeTransactions(const std::unordered_set<std::string>& txIdsToRemove) {
    for (const std::string& txId : txIdsToRemove) {
        auto it = transactions.find(txId);
        if (it == transactions.end()) {
            // يمكن أن نطلق استثناء هنا أو نُسجل خطأ، اعتماداً على مدى صرامة المتطلبات
            // حالياً، سنُسجل خطأ ونستمر.
            std::cerr << "Warning: Attempted to remove non-existent transaction from DAG: " << txId << std::endl;
            continue;
        }

        // 1. إزالة المعاملة من الخريطة الرئيسية
        transactions.erase(it);

        // 2. إزالة المعاملة من قائمة الـ tips (إذا كانت tip)
        tips.erase(txId);

        // 3. تحديث خرائط الأبناء والآباء
        // أولاً: تحديث أبناء هذه المعاملة (إذا كانت لها أبناء)
        // يجب أن نُزيل هذه المعاملة من قائمة آباء أبنائها
        auto children_it = childrenMap.find(txId);
        if (children_it != childrenMap.end()) {
            for (const std::string& childId : children_it->second) {
                auto& childParents = parentMap[childId];
                // إزالة txId من قائمة آباء childId
                childParents.erase(std::remove(childParents.begin(), childParents.end(), txId), childParents.end());
            }
            childrenMap.erase(txId); // إزالة إدخال هذه المعاملة من childrenMap
        }

        // ثانياً: تحديث آباء هذه المعاملة (إذا كان لها آباء)
        // لا نحتاج لعمل أي شيء خاص بالآباء هنا، فقط سنزيل إدخال هذه المعاملة من parentMap
        parentMap.erase(txId);

        // 4. هام: إضافة أي أبناء للمعاملة المحذوفة إلى الـ tips إذا أصبحوا الآن "يتامى"
        // (أي لم يعد لديهم آباء غير محذوفين).
        // هذه خطوة معقدة وقد تعتمد على تصميم الـ DAG الدقيق.
        // في نموذج بسيط، إذا تم حذف أب، سيظل الأبناء موجودين ويجب أن يبقى لهم آباء آخرون.
        // في الواقع، إذا تم حذف معاملة، فإن أبناءها لا يتأثرون إلا إذا كانت هي الأب الوحيد لهم.
        // في هذا التصميم، يجب على المنطق الخارجي (الذي يقوم بتضمين المعاملات في البلوكات)
        // التأكد من أن إزالة المعاملات لا تكسر سلسلة DAG، أي أن المعاملات المحذوفة
        // لن تترك فجوات تؤثر على صلاحية المعاملات التي لا تزال في DAG.
        // يمكننا تبسيط هذا المنطق: إذا تم حذف معاملة، فإن أبناءها لا يزالون يشيرون إليها كأب
        // (ولكنها غير موجودة). يمكن تصميم آلية DAG للتسامح مع "الآباء الغائبين" أو تتطلب
        // أن يكون لجميع المعاملات المؤكدة آباء موجودون.
        // لأغراض هذا الكود، سنفترض أن الإزالة تتم للمعاملات المؤكدة.
        // هذا الجزء قد يحتاج إلى مراجعة وتفصيل أكثر في نظام بلوكتشين حقيقي
        // لضمان سلامة الـ DAG بعد الإزالة.
    }
}

// جلب قائمة المعاملات الطرفية (tips)
std::vector<std::string> TransactionDAG::getTips() const {
    return std::vector<std::string>(tips.begin(), tips.end());
}

// التحقق مما إذا كانت المعاملة موجودة في الـ DAG
bool TransactionDAG::containsTransaction(const std::string& txId) const {
    return transactions.count(txId) > 0;
}

// جلب عدد المعاملات في الـ DAG
size_t TransactionDAG::size() const {
    return transactions.size();
}

// جلب عدد الـ tips في الـ DAG
size_t TransactionDAG::getTipsCount() const {
    return tips.size();
}

// مسح جميع المعاملات من الـ DAG
void TransactionDAG::clear() {
    transactions.clear();
    tips.clear();
    childrenMap.clear();
    parentMap.clear();
}

// دالة للمساعدة في تصحيح الأخطاء: طباعة حالة الـ DAG
void TransactionDAG::printDAGStatus() const {
    std::cout << "\n--- DAG Status ---" << std::endl;
    std::cout << "Total Transactions in DAG: " << transactions.size() << std::endl;
    std::cout << "Current Tips Count: " << tips.size() << std::endl;

    if (!tips.empty()) {
        std::cout << "Current Tips (first 5):" << std::endl;
        int count = 0;
        for (const auto& tipId : tips) {
            std::cout << "  - " << tipId.substr(0, 10) << "..." << std::endl;
            count++;
            if (count >= 5) break; // نطبع أول 5 فقط لتجنب الإطالة
        }
    }

    // يمكن إضافة طباعة لمحتويات الـ DAG بشكل أكثر تفصيلاً لأغراض التصحيح
    // مثلاً، طباعة أول 5 معاملات وتفاصيل آبائها وأبنائها.
    // if (!transactions.empty()) {
    //     std::cout << "\nSample Transactions (first 5):" << std::endl;
    //     int count = 0;
    //     for (const auto& pair : transactions) {
    //         std::cout << "  Tx ID: " << pair.first.substr(0, 10) << "..." << std::endl;
    //         if (parentMap.count(pair.first) && !parentMap.at(pair.first).empty()) {
    //             std::cout << "    Parents: ";
    //             for (const auto& parentId : parentMap.at(pair.first)) {
    //                 std::cout << parentId.substr(0, 8) << "... ";
    //             }
    //             std::cout << std::endl;
    //         }
    //         if (childrenMap.count(pair.first) && !childrenMap.at(pair.first).empty()) {
    //             std::cout << "    Children: ";
    //             for (const auto& childId : childrenMap.at(pair.first)) {
    //                 std::cout << childId.substr(0, 8) << "... ";
    //             }
    //             std::cout << std::endl;
    //         }
    //         count++;
    //         if (count >= 5) break;
    //     }
    // }
    std::cout << "--- End DAG Status ---\n" << std::endl;
}
