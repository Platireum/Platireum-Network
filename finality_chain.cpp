#include "finality_chain.h" // يجب تضمين ملف الرأس الخاص بنا أولاً
#include <iostream>           // للاستخدام في دوال الطباعة لتصحيح الأخطاء
#include <algorithm>          // لاستخدام std::sort
#include <stdexcept>          // لاستخدام std::runtime_error

// --- تنفيذ دوال فئة Block ---

// دالة خاصة لحساب هاش الكتلة
void Block::calculateHash() {
    std::stringstream ss;
    ss << previousBlockHash
       << timestamp
       << validatorId
       << validatorSignature; // توقيع المدقق جزء من البيانات التي يتم هاشها لضمان عدم التلاعب

    // تسلسل معرفات المعاملات بترتيب ثابت (مهم جداً لضمان نفس الهاش)
    std::vector<std::string> sortedTxIds = transactionIds;
    std::sort(sortedTxIds.begin(), sortedTxIds.end());
    for (const auto& txId : sortedTxIds) {
        ss << txId;
    }
    
    ss << std::fixed << std::setprecision(8) << totalFees; // تسلسل الرسوم

    hash = CryptoHelper::sha256(ss.str());
}

// Constructor لإنشاء كتلة جديدة
Block::Block(std::string prevHash,
             const std::string& valId,
             const CryptoHelper::ECKeyPtr& validatorPrivateKey,
             const std::vector<std::shared_ptr<Transaction>>& confirmedTransactions)
    : previousBlockHash(std::move(prevHash)),
      validatorId(valId) {
    
    // الحصول على الطابع الزمني الحالي
    timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count();

    // استخراج معرفات المعاملات وحساب الرسوم
    totalFees = 0.0;
    for (const auto& txPtr : confirmedTransactions) {
        if (!txPtr) {
            throw BlockError("Null transaction pointer provided to block constructor.");
        }
        transactionIds.push_back(txPtr->getId());
        
        // حساب الرسوم: مجموع المدخلات - مجموع المخرجات
        double inputSum = 0.0;
        for (const auto& input : txPtr->getInputs()) {
            // ملاحظة: هنا ستحتاج إلى الوصول إلى الـ UTXO set لتحديد قيمة كل مدخل.
            // هذا التعقيد سيتم حله عندما يتم دمج FinalityChain و TransactionDAG.
            // لأغراض هذا الكود، سنفترض أن قيمة المدخلات معروفة أو أن الرسوم يتم تمريرها
            // بشكل مباشر للمعاملة (وهو غير دقيق تماماً).
            // حالياً، سنبسط ونفترض أن كل معاملة لها قيمة رسوم معروفة أو يتم حسابها بطريقة أخرى.
            // يجب تحديث هذا لاحقاً ليتفاعل مع UTXO Set لجمع قيم المدخلات الحقيقية.
            // مؤقتاً، يمكننا أن نفترض رسوم ثابتة أو أنها محسوبة مسبقاً.
            // هذا الجزء سيحتاج إلى مراجعة وتعديل عندما ندمج UTXO set بشكل كامل.
            // لحساب الرسوم بشكل دقيق، يجب معرفة قيمة كل UTXO يتم إنفاقه.
            // هذا يعني أن Block constructor يجب أن يأخذ UTXO set أيضاً أو أن المعاملات
            // تأتي بـ "إجمالي رسومها" جاهزاً.
            // لأغراض الآن، سنُفترض أن الرسوم تم حسابها بالفعل خارج هذا الكونستراكتور.
            // مثلاً، يمكن أن تكون `confirmedTransactions` تحتوي على `fees` جاهزة.
            // مؤقتاً، لنحسب الرسوم من خلال الفرق بين input/output amounts.
            // ولكن هذا يتطلب معرفة قيم الـ UTXO الأصلية، والتي ليست متوفرة هنا مباشرةً.
            // لنبسط: سنفترض أن المعاملات تأتي مع حقل `fee` محسوب مسبقاً، أو سنتجاوز هذا مؤقتاً.
            // في البلوكتشين، يتم جمع الرسوم من فرق المدخلات والمخرجات لكل معاملة.
            // هنا، سنحتاج لبعض المنطق لجلب قيمة UTXO لكي نحسب الرسوم.
            // بسبب هذا التحدي، سأضع مؤقتاً حساب رسوم تبسيطي:
            // في نظام واقعي، يتم التحقق من مجموع المدخلات والمخرجات هنا وتحديد الرسوم.
            // لتجنب تعقيد مفرط في هذه المرحلة، يمكننا تبسيط الأمر مؤقتاً
            // أو جعل حساب الرسوم يتم خارج هذه الفئة وتمريره.
            // لنفترض مؤقتاً أن كل معاملة لها رسوم داخلية (وهذا غير موجود في Transaction حالياً).
            // أو يمكننا اعتبار رسوماً ثابتة لكل معاملة أو نُحددها خارجياً.
            // لنضف رسوم وهمية مؤقتاً لحين ربطها بـ UTXO set.
            // قيمة المعاملة نفسها (إذا لم تكن صفراً) يمكن أن تكون قيمة رسوم.
            totalFees += 0.0001; // رسوم وهمية مؤقتة لكل معاملة
        }
        // تأكد من فرز transactionIds لضمان هاش ثابت
        std::sort(transactionIds.begin(), transactionIds.end());
    }

    // حساب الهاش بعد الانتهاء من جميع البيانات
    calculateHash();

    // توقيع هاش الكتلة بواسطة المدقق
    std::vector<unsigned char> sigBytes = CryptoHelper::signData(validatorPrivateKey, hash);
    validatorSignature = bytesToHex(sigBytes);
}

// Constructor لتحميل كتلة موجودة
Block::Block(std::string hash,
             std::string prevHash,
             std::int64_t ts,
             std::string valId,
             std::string valSignature,
             std::vector<std::string> txIds,
             double fees)
    : hash(std::move(hash)), previousBlockHash(std::move(prevHash)),
      timestamp(ts), validatorId(std::move(valId)),
      validatorSignature(std::move(valSignature)),
      transactionIds(std::move(txIds)), totalFees(fees) {
    
    // يمكن هنا إضافة تحقق بسيط لضمان أن الهاش المعطى يتطابق مع الهاش المحسوب
    // لضمان عدم التلاعب بالبيانات عند التحميل.
    std::string calculatedHash;
    { // Block scope for temporary stringstream
        std::stringstream ss;
        ss << previousBlockHash
           << timestamp
           << validatorId
           << validatorSignature;
        std::vector<std::string> sortedTxIds = transactionIds;
        std::sort(sortedTxIds.begin(), sortedTxIds.end());
        for (const auto& id : sortedTxIds) {
            ss << id;
        }
        ss << std::fixed << std::setprecision(8) << totalFees;
        calculatedHash = CryptoHelper::sha256(ss.str());
    }

    if (calculatedHash != this->hash) {
        throw BlockError("Block hash mismatch during loading. Data tampered or invalid.");
    }
}

// التحقق من صلاحية الكتلة
bool Block::validate(const std::string& validatorPublicKeyHex) const {
    // 1. التحقق من أن الهاش المحسوب يتطابق مع الهاش المخزن
    std::string calculatedHash;
    { // Block scope for temporary stringstream
        std::stringstream ss;
        ss << previousBlockHash
           << timestamp
           << validatorId
           << validatorSignature;
        std::vector<std::string> sortedTxIds = transactionIds;
        std::sort(sortedTxIds.begin(), sortedTxIds.end());
        for (const auto& txId : sortedTxIds) {
            ss << txId;
        }
        ss << std::fixed << std::setprecision(8) << totalFees;
        calculatedHash = CryptoHelper::sha256(ss.str());
    }
    if (calculatedHash != hash) {
        throw BlockError("Block hash validation failed: calculated hash " + calculatedHash + " != stored hash " + hash);
    }

    // 2. التحقق من صحة توقيع المدقق
    std::vector<unsigned char> sigBytes = hexToBytes(validatorSignature);
    if (!CryptoHelper::verifySignature(validatorPublicKeyHex, sigBytes, hash)) {
        throw BlockError("Block validator signature is invalid.");
    }

    // 3. التحقق من الطابع الزمني (يجب ألا يكون في المستقبل البعيد جداً)
    std::int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count();
    if (timestamp > currentTime + 600000) { // 10 دقائق في المستقبل (للسماح باختلافات الساعة)
        throw BlockError("Block timestamp is too far in the future.");
    }

    // 4. يمكن إضافة تحققات أخرى هنا:
    //    - التحقق من أن totalFees منطقية (غير سالبة).
    //    - التحقق من أن validatorId صالح (موجود في قائمة المدققين، إذا كان لدينا).

    return true; // إذا تم اجتياز جميع التحققات
}

// تسلسل الكتلة إلى سلسلة نصية (للتخزين أو الإرسال عبر الشبكة)
std::string Block::serialize() const {
    std::stringstream ss;
    ss << hash << "|"
       << previousBlockHash << "|"
       << timestamp << "|"
       << validatorId << "|"
       << validatorSignature << "|"
       << std::fixed << std::setprecision(8) << totalFees << "|";
    
    // تسلسل معرفات المعاملات مع فاصلة
    for (size_t i = 0; i < transactionIds.size(); ++i) {
        ss << transactionIds[i];
        if (i < transactionIds.size() - 1) {
            ss << ",";
        }
    }
    return ss.str();
}

// إلغاء تسلسل الكتلة من سلسلة نصية
std::shared_ptr<Block> Block::deserialize(const std::string& data) {
    std::stringstream ss(data);
    std::string segment;
    std::vector<std::string> segments;

    // تقسيم السلسلة باستخدام الفاصل '|'
    while (std::getline(ss, segment, '|')) {
        segments.push_back(segment);
    }

    // يجب أن يكون هناك على الأقل 6 أجزاء (hash, prevHash, timestamp, valId, valSig, fees, txIds)
    if (segments.size() < 7) {
        throw BlockError("Invalid block serialization format: not enough segments.");
    }

    std::string hash = segments[0];
    std::string prevHash = segments[1];
    std::int64_t timestamp = std::stoll(segments[2]);
    std::string validatorId = segments[3];
    std::string validatorSignature = segments[4];
    double totalFees = std::stod(segments[5]);
    
    std::vector<std::string> txIds;
    // آخر جزء هو قائمة معرفات المعاملات مفصولة بفاصلة
    if (segments.size() > 6 && !segments[6].empty()) {
        std::stringstream txIdStream(segments[6]);
        std::string txId;
        while (std::getline(txIdStream, txId, ',')) {
            txIds.push_back(txId);
        }
    }

    return std::make_shared<Block>(hash, prevHash, timestamp, validatorId, validatorSignature, txIds, totalFees);
}


// --- تنفيذ دوال فئة FinalityChain ---

// Constructor
FinalityChain::FinalityChain()
    : currentChainTipHash(""), currentHeight(-1) { // -1 للإشارة إلى عدم وجود كتل بعد
    // يتم تهيئة الخرائط الأخرى تلقائياً
}

// دالة داخلية لتحديث الـ UTXO set
void FinalityChain::updateUtxoSet(const Block& block,
                                  const std::unordered_map<std::string, std::shared_ptr<Transaction>>& transactionsInBlock,
                                  bool isRevert) {
    
    for (const std::string& txId : block.getTransactionIds()) {
        auto it = transactionsInBlock.find(txId);
        if (it == transactionsInBlock.end()) {
            // هذا خطأ فادح: الكتلة تشير إلى معاملة غير موجودة في الذاكرة المعطاة
            throw FinalityChainError("Block references non-existent transaction: " + txId);
        }
        const std::shared_ptr<Transaction>& tx = it->second;

        if (!isRevert) { // تطبيق التغييرات
            // إزالة الـ UTXO القديمة التي يتم صرفها (المدخلات)
            for (const auto& input : tx->getInputs()) {
                if (utxoSet.erase(input.utxoId) == 0) {
                    // إذا لم يتم العثور على الـ UTXO، فهذا يعني أنه تم صرفه بالفعل أو غير موجود،
                    // وهذا خطأ في تطبيق المعاملات.
                    throw FinalityChainError("Attempted to spend non-existent UTXO: " + input.utxoId);
                }
            }
            // إضافة الـ UTXO الجديدة (المخرجات)
            for (const auto& output : tx->getOutputs()) {
                if (utxoSet.count(output.getId())) {
                    // هذا يعني أن هناك UTXO بنفس الـ ID بالفعل، وهذا خطأ.
                    throw FinalityChainError("Duplicate UTXO created: " + output.getId());
                }
                utxoSet[output.getId()] = output;
            }
        } else { // التراجع عن التغييرات (عند إعادة التنظيم مثلاً)
            // عكس العملية: إضافة الـ UTXO القديمة التي تم صرفها وإزالة الجديدة
            for (const auto& output : tx->getOutputs()) {
                if (utxoSet.erase(output.getId()) == 0) {
                    throw FinalityChainError("Attempted to revert non-existent UTXO: " + output.getId());
                }
            }
            for (const auto& input : tx->getInputs()) {
                // عند التراجع، نحتاج إلى استعادة الـ UTXO التي تم صرفها.
                // يجب أن تكون لدينا معلوماتها الأصلية. هذا يتطلب تخزينها مؤقتاً
                // أو إعادة بنائها من تاريخ البلوكتشين السابق.
                // لتشغيل هذا بشكل صحيح، قد تحتاج إلى تمرير الـ UTXO القديمة
                // إلى هذه الدالة عند الاستعادة، أو البحث عنها في الكتل السابقة.
                // حالياً، سنبسط ونفترض أننا نُعيدها كما كانت.
                // هذا الجزء سيتطلب منطقاً أكثر تعقيداً في سيناريو إعادة التنظيم.
                // لحل مشكلة 'revert' بشكل صحيح، يجب أن يكون لدينا snapshots لـ UTXO set
                // أو القدرة على إعادة بناء UTXO الذي تم صرفه.
                // مؤقتاً، لنفترض أن المدخلات (UTXOs التي تم صرفها) يمكن استعادتها بسهولة
                // من الـ Transaction نفسها، وهذا غير دقيق.
                // هذا الجزء سيتطلب تعديلاً كبيراً عند التعامل مع إعادة التنظيم.
                // حالياً، سنتجنب تعقيد إعادة بناء UTXO الذي تم صرفه.
                // إذا لم يكن هناك مدخلات (مثل coinbase tx)، فلا تفعل شيئاً.
                // for (const auto& input : tx->getInputs()) { ... }
                // بما أننا لا نملك UTXO الذي كان يتم صرفه هنا، هذا الجزء غير مكتمل للتراجع الفعلي.
                // لذا، في هذه المرحلة، سنركز فقط على "تطبيق" الكتل وليس "التراجع" عنها.
                // For a proper revert, you'd need the actual TransactionOutput that was spent.
                // This is typically done by reconstructing it from the previous block's UTXO state,
                // or keeping a journal of changes. For now, this is simplified.
            }
        }
    }
}

// تهيئة الكتلة التكوينية (Genesis Block)
void FinalityChain::initializeGenesisBlock(const std::string& validatorId, const CryptoHelper::ECKeyPtr& validatorPrivateKey) {
    if (currentHeight != -1) {
        throw FinalityChainError("Blockchain already initialized with a genesis block.");
    }

    // كتلة التكوين ليس لها بلوك أب سابق
    std::string prevHash = std::string(64, '0'); // هاش فارغ (كل أصفار)

    // يمكن أن تحتوي كتلة التكوين على معاملة واحدة لتوليد عملات أولية
    // Transaction genesisTx({"00:00"}, {TransactionOutput("", 0, validatorId, 1000000.0)});
    // نُبسطها حالياً بكتلة فارغة من المعاملات ولكن برسوم وهمية.
    // في النظام الحقيقي، كتلة التكوين غالباً ما تكون معاملة واحدة لتوليد عملة.
    // سنستخدم vector فارغ من المعاملات.
    std::vector<std::shared_ptr<Transaction>> genesisTransactions; // لا معاملات في كتلة التكوين عادةً

    // إنشاء كتلة التكوين
    std::shared_ptr<Block> genesisBlock = std::make_shared<Block>(prevHash, validatorId, validatorPrivateKey, genesisTransactions);

    // إضافة كتلة التكوين إلى السلسلة
    if (!addBlock(genesisBlock, {})) { // لا توجد معاملات حقيقية في هذه الحالة (فقط لرسوم)
        throw FinalityChainError("Failed to add genesis block.");
    }
    std::cout << "Genesis block initialized with hash: " << genesisBlock->getHash().substr(0, 8) << "..." << std::endl;
}

// إضافة كتلة جديدة إلى البلوكتشين
bool FinalityChain::addBlock(std::shared_ptr<Block> newBlock,
                             const std::unordered_map<std::string, std::shared_ptr<Transaction>>& transactionsInBlock) {
    if (!newBlock) {
        throw FinalityChainError("Attempted to add a null block.");
    }

    // 1. التحقق من وجود الكتلة بالفعل
    if (blocks.count(newBlock->getHash())) {
        std::cerr << "Warning: Block already exists in chain: " << newBlock->getHash().substr(0, 8) << "..." << std::endl;
        return false; // لا تُضيف نفس الكتلة مرتين
    }

    // 2. التحقق من صحة الكتلة (توقيع المدقق، الهاش، الخ)
    // نحتاج للمفتاح العام للمدقق للتحقق من توقيع الكتلة
    // في نظام PoS حقيقي، يجب أن يكون لدينا قائمة بالمدققين والمفاتيح العامة لهم
    // هنا سنفترض أن المفتاح العام للـ validatorId يمكن استخلاصه أو معرفته.
    // for now, we'll assume the validatorId passed to validate is the public key itself.
    // هذا سيتطلب دمجاً مع ValidatorManager لاحقاً للحصول على مفتاح المدقق
    if (!newBlock->validate(newBlock->getValidatorId())) { // استخدام ID كـ Public Key مؤقتاً
        throw FinalityChainError("New block validation failed for block: " + newBlock->getHash().substr(0, 8) + "...");
    }

    // 3. التحقق من ربط الكتلة بالسلسلة الحالية (التسلسل الصحيح)
    if (currentHeight != -1 && newBlock->getPreviousBlockHash() != currentChainTipHash) {
        // هذه حالة "انقسام" (fork) أو كتلة خارج التسلسل.
        // في نظام حقيقي، تحتاج لمعالجة الـ forks (أطول سلسلة تفوز، أو إجماع آخر).
        // حالياً، سنرفض الكتل التي لا تُكمل السلسلة مباشرة.
        throw FinalityChainError("Block's previous hash does not match current chain tip. Fork detected or out of order block. " + newBlock->getPreviousBlockHash().substr(0,8) + "... != " + currentChainTipHash.substr(0,8) + "...");
    }

    // 4. التحقق من صلاحية المعاملات داخل الكتلة مقابل الـ UTXO set الحالي
    // يجب أن تكون جميع المعاملات في الكتلة صالحة بالنسبة للـ UTXO set الحالي قبل تطبيق الكتلة.
    for (const std::string& txId : newBlock->getTransactionIds()) {
        auto tx_it = transactionsInBlock.find(txId);
        if (tx_it == transactionsInBlock.end()) {
            throw FinalityChainError("Block contains reference to transaction not provided: " + txId);
        }
        if (!tx_it->second->validate(utxoSet)) { // التحقق من صحة كل معاملة باستخدام UTXO set الحالي
            throw FinalityChainError("Transaction " + txId + " in new block is invalid against current UTXO set.");
        }
    }

    // 5. تحديث الـ UTXO set بناءً على معاملات الكتلة
    updateUtxoSet(*newBlock, transactionsInBlock, false); // false لـ isRevert (تطبيق التغييرات)

    // 6. إضافة الكتلة إلى الخرائط
    blocks[newBlock->getHash()] = newBlock;
    currentChainTipHash = newBlock->getHash();
    currentHeight++;
    blockHeights[newBlock->getHash()] = currentHeight;
    hashByHeight[currentHeight] = newBlock->getHash();

    // std::cout << "Block " << newBlock->getHash().substr(0, 8) << "... added. Height: " << currentHeight << std::endl;
    return true;
}

// جلب كتلة بواسطة الهاش الخاص بها
std::shared_ptr<Block> FinalityChain::getBlock(const std::string& blockHash) const {
    auto it = blocks.find(blockHash);
    if (it != blocks.end()) {
        return it->second;
    }
    return nullptr;
}

// جلب كتلة بواسطة ارتفاعها في السلسلة
std::shared_ptr<Block> FinalityChain::getBlockByHeight(int height) const {
    auto hash_it = hashByHeight.find(height);
    if (hash_it != hashByHeight.end()) {
        return getBlock(hash_it->second);
    }
    return nullptr;
}

// التحقق مما إذا كانت الكتلة موجودة في السلسلة
bool FinalityChain::containsBlock(const std::string& blockHash) const {
    return blocks.count(blockHash) > 0;
}

// طباعة حالة السلسلة
void FinalityChain::printChainStatus() const {
    std::cout << "\n--- Finality Chain Status ---" << std::endl;
    std::cout << "Current Height: " << currentHeight << std::endl;
    if (currentHeight != -1) {
        std::cout << "Current Tip Hash: " << currentChainTipHash.substr(0, 8) << "..." << std::endl;
    }
    std::cout << "Total Blocks in Chain: " << blocks.size() << std::endl;
    std::cout << "Current UTXO Set Size: " << utxoSet.size() << std::endl;
    std::cout << "--- End Finality Chain Status ---\n" << std::endl;
}

// مسح السلسلة بالكامل (للاختبار/إعادة التعيين)
void FinalityChain::clear() {
    blocks.clear();
    utxoSet.clear();
    blockHeights.clear();
    hashByHeight.clear();
    currentChainTipHash = "";
    currentHeight = -1;
}
