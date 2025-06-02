#include "transaction_dag.h"
#include <iostream>      // للاستخدام في دوال الطباعة لتصحيح الأخطاء
#include <queue>         // For BFS/topological sort in getTransactionsToProcess

// --- تنفيذ دوال فئة TransactionDAG ---

// Constructor
TransactionDAG::TransactionDAG() {
    // لا شيء خاص للتهيئة هنا، حيث يتم تهيئة الخرائط والمجموعات تلقائياً.
}

// دالة مساعدة لتحديث المعاملات "الطرفية" (tips)
void TransactionDAG::updateTips(const std::string& newTxId, const std::vector<std::string>& parentTxIds) {
    // 1. إذا كانت المعاملة الجديدة هي أول معاملة في الـ DAG، تصبح هي الـ tip الوحيد
    // هذا الشرط يتم التحقق منه فقط عند إضافة المعاملة الأولى.
    // في الواقع، إذا كان الـ DAG فارغاً، فإن المعاملة الأولى ستصبح tip افتراضياً.
    // إذا كان الـ DAG يحتوي بالفعل على معاملات، فإن المعاملة الجديدة يجب أن تشير إلى آباء.
    if (transactions.size() == 1 && parentTxIds.empty()) { // This means it's the very first transaction
        tips.insert(newTxId);
        return;
    }

    // 2. أي من الآباء الذين تم الإشارة إليهم من قبل المعاملة الجديدة لم يعد "tip"
    for (const std::string& parentId : parentTxIds) {
        // إذا كان الأب موجوداً في قائمة الـ tips، أزله
        tips.erase(parentId); 
    }

    // 3. المعاملة الجديدة نفسها تصبح "tip" لأنها لم يتم الإشارة إليها كـ "أب" بعد
    // (ما لم يكن لديها أبناء بالفعل، وهو ما لا ينبغي أن يحدث عند الإضافة الأولية)
    tips.insert(newTxId);
}

// دالة مساعدة للتحقق من وجود المعاملات الأب
bool TransactionDAG::validateParentExistence(const std::vector<std::string>& parentTxIds) const {
    // إذا كان الـ DAG فارغاً، فإن المعاملة الأولى (Coinbase أو Genesis Transaction) لا تحتاج إلى آباء.
    // إذا كان الـ DAG غير فارغ، فيجب أن تشير المعاملة الجديدة إلى آباء.
    if (transactions.empty()) {
        // إذا كانت المعاملة الأولى لا تحتوي على آباء، فهي صالحة (قد تكون معاملة تأسيسية)
        // إذا كانت تحتوي على آباء في DAG فارغ، فهذا خطأ منطقي (لا يمكن أن يكون هناك آباء)
        if (!parentTxIds.empty()) {
            throw DAGError("First transaction in DAG cannot have parents.");
        }
        return true; // المعاملة الأولى بدون آباء
    } else {
        // إذا كان الـ DAG غير فارغ، فيجب أن يكون هناك آباء
        if (parentTxIds.empty()) {
            throw DAGError("New transaction must reference parent transactions in a non-empty DAG.");
        }
    }

    for (const std::string& parentId : parentTxIds) {
        if (transactions.find(parentId) == transactions.end()) {
            // إذا لم يتم العثور على أي من الآباء في الـ DAG
            return false; // لا نرمي استثناء هنا، بل نُرجع false ونترك دالة addTransaction لتقرر.
        }
    }
    return true;
}

// إضافة معاملة جديدة إلى الـ DAG
void TransactionDAG::addTransaction(std::shared_ptr<Transaction> tx,
                                    const std::unordered_map<std::string, TransactionOutput>& currentUtxoSet) {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن

    if (!tx) {
        throw DAGError("Attempted to add a null transaction to DAG.");
    }
    const std::string& txId = tx->getId();

    // 1. التحقق مما إذا كانت المعاملة موجودة بالفعل
    if (transactions.count(txId)) {
        throw DAGError("Transaction already exists in DAG: " + txId);
    }

    // 2. التحقق من وجود المعاملات الأب في الـ DAG
    const std::vector<std::string>& parentTxIds = tx->getParents();
    // إذا كانت هذه هي المعاملة الأولى (الـ DAG فارغ) وليس لها آباء، فهي صالحة.
    // بخلاف ذلك، يجب أن تكون جميع المعاملات الأب موجودة في الـ DAG أو تكون مؤكدة (خارج نطاق هذا DAG).
    // لأغراض هذا الـ DAG، نفترض أن الآباء يجب أن يكونوا موجودين هنا.
    if (!validateParentExistence(parentTxIds)) {
        throw DAGError("One or more parent transactions not found in DAG.");
    }
    
    // 3. التحقق من صحة المعاملة نفسها (باستخدام دالة validate الخاصة بالمعاملة)
    // هذا هو المكان الذي نستخدم فيه currentUtxoSet.
    // يمكن أن تطلق دالة validate استثناء TransactionError
    if (!tx->getInputs().empty()) { // Coinbase transactions don't need UTXO validation
        if (!tx->validate(currentUtxoSet)) {
            // Transaction::validate will throw TransactionError itself if validation fails
            // This line might not be reached if validate throws
            throw TransactionError("Transaction validation failed for " + txId);
        }
    }

    // 4. إضافة المعاملة إلى الخريطة الرئيسية
    transactions[txId] = tx;

    // 5. تحديث خرائط الأبناء والآباء
    for (const std::string& parentId : parentTxIds) {
        childrenMap[parentId].insert(txId);
        parentMap[txId].insert(parentId);
    }

    // 6. تحديث قائمة المعاملات الطرفية (tips)
    updateTips(txId, parentTxIds);

    // std::cout << "Transaction " << txId.substr(0, 8) << "... added to DAG. Tips count: " << tips.size() << std::endl;
}

// استرجاع معاملة من الـ DAG
std::shared_ptr<Transaction> TransactionDAG::getTransaction(const std::string& txId) const {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن للقراءة
    auto it = transactions.find(txId);
    if (it != transactions.end()) {
        return it->second;
    }
    return nullptr; // نُعيد مؤشر فارغ إذا لم يتم العثور على المعاملة
}

// إزالة مجموعة من المعاملات من الـ DAG (بعد تضمينها في بلوك)
void TransactionDAG::removeTransactions(const std::unordered_set<std::string>& txIdsToRemove) {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن

    for (const std::string& txId : txIdsToRemove) {
        auto it = transactions.find(txId);
        if (it == transactions.end()) {
            std::cerr << "Warning: Attempted to remove non-existent transaction from DAG: " << txId << std::endl;
            continue;
        }

        // 1. إزالة المعاملة من الخريطة الرئيسية
        transactions.erase(it);

        // 2. إزالة المعاملة من قائمة الـ tips (إذا كانت tip).
        // ملاحظة: إذا تم إزالة معاملة وكانت tip، فهذا يعني أنها لم يتم الإشارة إليها من قبل أي معاملة أخرى في DAG.
        // إذا كان لها أبناء، فإن إزالتها ستجعلها "غير مؤكدة" وتتطلب معالجة خاصة.
        // ولكن منطقياً، عندما تتم إزالة معاملة من DAG، فهذا يعني أنها تم تأكيدها في البلوك.
        // لذلك، لا ينبغي أن تكون tip.
        tips.erase(txId); 

        // 3. تحديث خرائط الأبناء والآباء
        // أولاً: تحديث أبناء هذه المعاملة (إذا كانت لها أبناء)
        // يجب أن نُزيل هذه المعاملة من قائمة آباء أبنائها
        auto children_it = childrenMap.find(txId);
        if (children_it != childrenMap.end()) {
            for (const std::string& childId : children_it->second) {
                // إزالة txId من مجموعة آباء childId
                if (parentMap.count(childId)) {
                    parentMap[childId].erase(txId);
                    // إذا أصبح الابن الآن "يتيم" (ليس لديه آباء مؤكدين في DAG)، فقد نحتاج لمعالجة.
                    // في أنظمة DAG الحقيقية، الأبناء قد يشيرون إلى آباء متعددين، بعضهم قد يؤكد.
                    // المنطق الأكثر تعقيدًا سيضيف هؤلاء الأبناء إلى tips إذا أصبحت جميع آبائهم
                    // مؤكدين أو تم إزالتهم من الـ DAG.
                    // حالياً، سنفترض أن الابن سيبقى في الـ DAG يشير إلى آباء آخرين إذا وجدت.
                }
            }
            childrenMap.erase(txId); // إزالة إدخال هذه المعاملة من childrenMap
        }

        // ثانياً: تحديث آباء هذه المعاملة (إذا كان لها آباء)
        // يجب أن نُزيل هذه المعاملة من قائمة أبناء آبائها
        auto parent_of_removed_tx_it = parentMap.find(txId);
        if (parent_of_removed_tx_it != parentMap.end()) {
            for (const std::string& parentId : parent_of_removed_tx_it->second) {
                if (childrenMap.count(parentId)) {
                    childrenMap[parentId].erase(txId);
                    // إذا لم يعد للأب أي أبناء في الـ DAG، فقد يصبح tip جديداً
                    if (childrenMap[parentId].empty()) {
                        tips.insert(parentId);
                    }
                }
            }
            parentMap.erase(txId); // إزالة إدخال هذه المعاملة من parentMap
        }
    }
}

// جلب قائمة المعاملات الطرفية (tips)
std::vector<std::string> TransactionDAG::getTips() const {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن للقراءة
    return std::vector<std::string>(tips.begin(), tips.end());
}

// التحقق مما إذا كانت المعاملة موجودة في الـ DAG
bool TransactionDAG::containsTransaction(const std::string& txId) const {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن للقراءة
    return transactions.count(txId) > 0;
}

// جلب عدد المعاملات في الـ DAG
size_t TransactionDAG::size() const {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن للقراءة
    return transactions.size();
}

// جلب عدد الـ tips في الـ DAG
size_t TransactionDAG::getTipsCount() const {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن للقراءة
    return tips.size();
}

// مسح جميع المعاملات من الـ DAG
void TransactionDAG::clear() {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن
    transactions.clear();
    tips.clear();
    childrenMap.clear();
    parentMap.clear();
}

// اختيار المعاملات للمعالجة (لتضمينها في بلوك)
std::vector<std::shared_ptr<Transaction>> TransactionDAG::getTransactionsToProcess(size_t maxTransactions) const {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن

    std::vector<std::shared_ptr<Transaction>> selectedTransactions;
    if (transactions.empty()) {
        return selectedTransactions;
    }

    // نحتاج إلى تحديد المعاملات التي يمكن معالجتها.
    // هذه هي المعاملات التي تكون جميع آبائها إما:
    // 1. موجودة بالفعل في DAG.
    // 2. أو سبق أن تمت معالجتها (تم تضمينها في بلوك سابق).
    // هنا، سنبسط الأمر ونفترض أننا نختار المعاملات "الطرفية" في الـ DAG الحالي
    // التي ليس لديها آباء غير موجودين في الـ DAG نفسه.
    // الأسلوب الأكثر شيوعًا هو ترتيب طوبولوجي (Topological Sort) للمعاملات.
    
    // لتبسيط عملية الاختيار حاليًا، سنختار المعاملات التي ليس لديها أي آباء غير مؤكدين (داخل DAG).
    // في نظام DAG معقد، قد تحتاج إلى خوارزمية اختيار أكثر تعقيداً (مثل اختيار الأقدم، الأكثر رسوماً).

    // خوارزمية مبسطة لاختيار المعاملات (BFS-like approach)
    // 1. حساب درجة "in-degree" لكل معاملة (عدد آبائها غير المؤكدين).
    // 2. إضافة المعاملات التي لها in-degree = 0 (ليس لديها آباء غير مؤكدين) إلى قائمة الانتظار.
    // 3. معالجة المعاملات من قائمة الانتظار:
    //    - إضافة المعاملة إلى قائمة المعاملات المختارة.
    //    - تقليل in-degree لأبنائها.
    //    - إذا أصبح in-degree لأحد الأبناء 0، أضفه إلى قائمة الانتظار.

    std::unordered_map<std::string, int> inDegree;
    std::queue<std::string> q;

    // تهيئة in-degree لجميع المعاملات في الـ DAG
    for (const auto& pair : transactions) {
        const std::string& txId = pair.first;
        if (parentMap.count(txId)) {
            inDegree[txId] = parentMap.at(txId).size();
        } else {
            inDegree[txId] = 0;
        }
        
        // إذا كان in-degree = 0، فهذا يعني أن جميع آبائها إما غير موجودين في DAG
        // (أي تم تأكيدهم مسبقاً) أو أنها معاملة أولية (بدون آباء).
        if (inDegree[txId] == 0) {
            q.push(txId);
        }
    }

    while (!q.empty() && selectedTransactions.size() < maxTransactions) {
        std::string currentTxId = q.front();
        q.pop();

        if (transactions.count(currentTxId)) {
            selectedTransactions.push_back(transactions.at(currentTxId));
        } else {
            // هذا لا ينبغي أن يحدث إذا كانت transactions و inDegree متزامنة
            continue;
        }

        // تقليل in-degree لأبناء المعاملة الحالية
        if (childrenMap.count(currentTxId)) {
            for (const std::string& childId : childrenMap.at(currentTxId)) {
                if (inDegree.count(childId)) { // تأكد من أن الابن لا يزال موجوداً في DAG
                    inDegree[childId]--;
                    if (inDegree[childId] == 0) {
                        q.push(childId);
                    }
                }
            }
        }
    }

    // يمكن هنا فرز selectedTransactions بناءً على عوامل إضافية (مثل الطابع الزمني أو الرسوم)
    // std::sort(selectedTransactions.begin(), selectedTransactions.end(), 
    //           [](const std::shared_ptr<Transaction>& a, const std::shared_ptr<Transaction>& b) {
    //               return a->getTimestamp() < b->getTimestamp(); // الأقدم أولاً
    //           });

    return selectedTransactions;
}

// دالة للمساعدة في تصحيح الأخطاء: طباعة حالة الـ DAG
void TransactionDAG::printDAGStatus() const {
    std::lock_guard<std::mutex> lock(dagMutex); // حماية الوصول المتزامن للقراءة
    std::cout << "\n--- DAG Status ---" << std::endl;
    std::cout << "Total Transactions in DAG: " << transactions.size() << std::endl;
    std::cout << "Current Tips Count: " << tips.size() << std::endl;

    if (!tips.empty()) {
        std::cout << "Current Tips (first 5):" << std::endl;
        int count = 0;
        for (const auto& tipId : tips) {
            std::cout << "  - " << tipId.substr(0, 10) << "..." << std::endl;
            count++;
            if (count >= 5) break; 
        }
    }

    if (!transactions.empty()) {
        std::cout << "\nSample Transactions (first 5):" << std::endl;
        int count = 0;
        for (const auto& pair : transactions) {
            std::cout << "  Tx ID: " << pair.first.substr(0, 10) << "..." << std::endl;
            if (parentMap.count(pair.first) && !parentMap.at(pair.first).empty()) {
                std::cout << "    Parents: ";
                for (const auto& parentId : parentMap.at(pair.first)) {
                    std::cout << parentId.substr(0, 8) << "... ";
                }
                std::cout << std::endl;
            }
            if (childrenMap.count(pair.first) && !childrenMap.at(pair.first).empty()) {
                std::cout << "    Children: ";
                for (const auto& childId : childrenMap.at(pair.first)) {
                    std::cout << childId.substr(0, 8) << "... ";
                }
                std::cout << std::endl;
            }
            count++;
            if (count >= 5) break;
        }
    }
    std::cout << "--- End DAG Status ---\n" << std::endl;
}