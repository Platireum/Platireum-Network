#include "node.h"
#include <iostream>
#include <random>
#include <algorithm> // For std::remove_if, std::sort
#include <cassert>   // For assert in debugging

// --- تنفيذ دوال فئة Node ---

// Constructor
Node::Node(const std::string& initialId, double minStake, size_t maxTxPerBlock)
    : nodeId(initialId), minStakeAmount(minStake), maxTransactionsPerBlock(maxTxPerBlock) {
    // إنشاء زوج المفاتيح الخاص والعام لهذه العقدة
    privateKey = CryptoHelper::generateKeyPair();
    publicKey = CryptoHelper::getPublicKeyHex(privateKey);

    log("Node " + nodeId + " initialized with Public Key: " + publicKey.substr(0, 8) + "...");
}

// دالة تسجيل بسيطة
void Node::log(const std::string& message) const {
    std::cout << "[Node " << nodeId << " - " << publicKey.substr(0, 8) << "...] " << message << std::endl;
}

// تهيئة العقدة وإنشاء كتلة التكوين إذا لزم الأمر
void Node::initialize(bool isGenesisNode, std::shared_ptr<std::unordered_map<std::string, std::shared_ptr<Node>>> networkNodes) {
    this->allNetworkNodes = networkNodes;

    // تهيئة كتلة التكوين إذا كانت هذه العقدة هي العقدة الأولى
    if (isGenesisNode) {
        log("Initializing genesis block...");
        finalityChain.initializeGenesisBlock(publicKey, privateKey);
        // يجب أن تضاف مكافأة كتلة التكوين إلى UTXO Set الخاص بالعقدة الجينية
        // أو حسابها كمعاملة "توليد عملة" (coinbase transaction)
        // حالياً، نعتبر أن initializeGenesisBlock() تعالج هذا.
        // يمكننا إضافة UTXO يدوياً هنا لتمثيل المكافأة الأولية
        TransactionOutput genesisCoinbaseOutput("", 0, publicKey, 1000000.0); // 1 مليون عملة للجينيسيس
        // نُعدّل txId و outputIndex لاحقاً ليتوافق مع الهاش الفعلي للكتلة الجينية.
        // لكن بما أن الـ UTXO set هو داخل FinalityChain، فإن initializeGenesisBlock
        // هي التي يجب أن تُضيف هذا الـ UTXO.
        // إذا كان genesisTxId للكتلة الجينية، يجب أن تكون هذه هي المعاملة الأولى.
        // بما أن initializeGenesisBlock لا تأخذ معاملات، فهذا يعني أن مكافأة كتلة الجينيسيس
        // يجب أن تُضاف بواسطة FinalityChain نفسها.
        // لتبسيط الأمر الآن، لنفترض أن initializeGenesisBlock تضيف UTXO للمدقق الجيني.
        // (وهو ليس مضمّنًا في FinalityChain::initializeGenesisBlock حاليًا، سنضيفه هناك لاحقاً).
        
        // مؤقتاً، نضيف UTXO "وهمي" للعقدة الجينية لكي تتمكن من إنشاء معاملات لاحقاً.
        // هذا ليس هو المكان الصحيح له، يجب أن يكون ضمن منطق FinalityChain
        // ولكن للتجربة الأولية:
        // finalityChain.getUtxoSet()[genesisCoinbaseOutput.getId()] = genesisCoinbaseOutput;
        // لا، هذا غير صحيح، الـ UTXO يجب أن ينشأ من معاملة مؤكدة في الكتلة.
        // يجب أن يكون هناك معاملة توليد عملة (coinbase transaction) في كتلة التكوين.
        // سنتجاهل هذا مؤقتاً ونفترض أن initializeGenesisBlock ستقوم بذلك.
    }

    log("Node initialized successfully.");
}

// إنشاء وإرسال معاملة جديدة
std::shared_ptr<Transaction> Node::createAndSendTransaction(
    const CryptoHelper::ECKeyPtr& senderPrivateKey,
    const std::string& recipientPublicKey,
    double amount,
    const std::vector<TransactionOutput>& parentUtxos) {

    // 1. حساب مجموع المدخلات
    double inputSum = 0.0;
    std::vector<TransactionInput> inputs;
    for (const auto& utxo : parentUtxos) {
        // يجب أن نتحقق من أن هذا الـ UTXO موجود في الـ UTXO set الحالي للعقدة
        // هذا يتطلب الوصول إلى finalityChain.getUtxoSet()
        if (finalityChain.getUtxoSet().find(utxo.getId()) == finalityChain.getUtxoSet().end()) {
            throw NodeError("Attempted to spend non-existent UTXO: " + utxo.getId());
        }
        if (utxo.owner != CryptoHelper::getPublicKeyHex(senderPrivateKey)) {
            throw NodeError("Attempted to spend UTXO not owned by sender: " + utxo.getId());
        }
        inputSum += utxo.amount;
    }

    if (inputSum < amount) {
        throw NodeError("Insufficient funds. Available: " + std::to_string(inputSum) + ", Required: " + std::to_string(amount));
    }

    // 2. تحديد المخرجات
    std::vector<TransactionOutput> outputs;
    outputs.emplace_back("", 0, recipientPublicKey, amount); // خرج للمستلم
    
    double changeAmount = inputSum - amount;
    if (changeAmount > 0) {
        outputs.emplace_back("", 0, CryptoHelper::getPublicKeyHex(senderPrivateKey), changeAmount); // خرج الباقي للمرسل
    }
    
    // 3. إنشاء المعاملة (ستحسب الـ txId مؤقتاً)
    std::vector<std::string> parentTxs; // في هذه المرحلة، لا نحدد الآباء بعد
    std::shared_ptr<Transaction> newTx = std::make_shared<Transaction>(inputs, outputs, parentTxs);

    // 4. تحديث المدخلات بالتوقيعات بعد معرفة الـ txId
    // يجب أن نقوم بهذا بعد إنشاء المعاملة وحساب الـ txId الخاص بها
    std::vector<TransactionInput> signedInputs;
    for (const auto& utxo : parentUtxos) {
        signedInputs.push_back(
            Transaction::createSignedInput(utxo.getId(), senderPrivateKey, newTx->getId())
        );
    }
    newTx->setInputs(signedInputs); // تحديث المدخلات الموقعة في المعاملة

    // 5. التحقق من صلاحية المعاملة قبل الإضافة والنشر
    if (!newTx->validate(finalityChain.getUtxoSet())) {
        throw NodeError("Created transaction is invalid. Cannot send.");
    }

    log("Created transaction: " + newTx->getId().substr(0, 8) + "...");
    
    // 6. معالجة المعاملة محلياً وإرسالها للشبكة
    processIncomingTransaction(newTx); // تضيفها إلى الـ DAG محلياً
    broadcastTransaction(newTx);       // تبثها للشبكة

    return newTx;
}

// استقبال ومعالجة معاملة واردة
void Node::receiveTransaction(std::shared_ptr<Transaction> tx) {
    std::lock_guard<std::mutex> lock(nodeMutex); // حماية الموارد المشتركة
    processIncomingTransaction(tx);
}

// استقبال ومعالجة كتلة واردة
void Node::receiveBlock(std::shared_ptr<Block> block) {
    std::lock_guard<std::mutex> lock(nodeMutex); // حماية الموارد المشتركة
    processIncomingBlock(block);
}

// معالجة معاملة واردة (داخلية)
void Node::processIncomingTransaction(std::shared_ptr<Transaction> tx) {
    if (!tx || knownTransactions.count(tx->getId())) {
        return; // المعاملة فارغة أو معروفة بالفعل
    }

    try {
        // 1. التحقق من صحة المعاملة
        if (!tx->validate(finalityChain.getUtxoSet())) {
            log("Received invalid transaction (validation failed): " + tx->getId().substr(0, 8) + "...");
            return;
        }

        // 2. إضافة المعاملة إلى الـ DAG (تحتوي على آبائها)
        dag.addTransaction(tx);
        knownTransactions.insert(tx->getId()); // إضافة إلى المعاملات المعروفة

        log("Processed new transaction: " + tx->getId().substr(0, 8) + "... (DAG Size: " + std::to_string(dag.size()) + ")");

        // 3. إعادة بث المعاملة (إذا لم يتم بثها مسبقاً من قبل هذه العقدة)
        // يجب أن يكون هناك آلية لمنع الحلقات في البث (gossip protocol)
        // حالياً، سنبثها فقط
        // broadcastTransaction(tx); // يمكن إزالة هذا لمنع الإعادة اللانهائية في المحاكاة البسيطة
                                    // ونفترض أن receiveTransaction في الشبكة تقوم بالبث.

    } catch (const TransactionError& e) {
        log("Transaction processing error (TransactionError): " + std::string(e.what()));
    } catch (const DAGError& e) {
        log("Transaction processing error (DAGError): " + std::string(e.what()));
    } catch (const std::exception& e) {
        log("Unknown error processing transaction: " + std::string(e.what()));
    }
}

// معالجة كتلة واردة (داخلية)
void Node::processIncomingBlock(std::shared_ptr<Block> block) {
    if (!block || knownBlocks.count(block->getHash())) {
        return; // الكتلة فارغة أو معروفة بالفعل
    }

    try {
        // 1. التحقق من صلاحية الكتلة (توقيع المدقق، الهاش، الخ)
        // استخدام publicKey الخاص بالمدقق للتحقق
        if (!block->validate(block->getValidatorId())) { // يجب استبدالها بالمفتاح العام الحقيقي
            log("Received invalid block (validation failed): " + block->getHash().substr(0, 8) + "...");
            return;
        }

        // 2. جمع كائنات المعاملات الفعلية من الـ DAG (أو أي مكان آخر)
        // هذا يتطلب أن تكون المعاملات موجودة في الـ DAG أو pool لدى العقدة.
        // في نظام حقيقي، ستطلب العقدة المعاملات من النظراء إذا لم تكن لديها.
        std::unordered_map<std::string, std::shared_ptr<Transaction>> transactionsInBlock;
        for (const std::string& txId : block->getTransactionIds()) {
            std::shared_ptr<Transaction> tx = dag.getTransaction(txId);
            if (!tx) {
                // إذا لم يتم العثور على المعاملة في الـ DAG المحلي، فهذا يعني أنها مفقودة.
                // في سيناريو حقيقي، قد تطلبها العقدة من peer آخر.
                // حالياً، هذا يعتبر خطأ، ويجب أن يتم منع الكتلة التي تحتوي على معاملات مفقودة.
                throw NodeError("Block " + block->getHash().substr(0, 8) + "... references unknown transaction: " + txId.substr(0, 8) + "...");
            }
            transactionsInBlock[txId] = tx;
        }

        // 3. إضافة الكتلة إلى السلسلة النهائية
        // FinalityChain ستقوم بالتحقق من صحة المعاملات مقابل الـ UTXO set الحالي.
        if (finalityChain.addBlock(block, transactionsInBlock)) {
            knownBlocks.insert(block->getHash());
            log("Processed new block: " + block->getHash().substr(0, 8) + "... (Height: " + std::to_string(finalityChain.getCurrentHeight()) + ")");

            // 4. إزالة المعاملات المؤكدة من الـ DAG
            std::unordered_set<std::string> confirmedTxIds(block->getTransactionIds().begin(), block->getTransactionIds().end());
            dag.removeTransactions(confirmedTxIds);
            log("Removed " + std::to_string(confirmedTxIds.size()) + " confirmed transactions from DAG.");

            // 5. إعادة بث الكتلة
            // broadcastBlock(block); // يمكن إزالة هذا في المحاكاة البسيطة
        } else {
            log("Received block " + block->getHash().substr(0, 8) + "... but it was not added to chain (e.g., fork or invalid).");
        }
    } catch (const BlockError& e) {
        log("Block processing error (BlockError): " + std::string(e.what()));
    } catch (const FinalityChainError& e) {
        log("Block processing error (FinalityChainError): " + std::string(e.what()));
    } catch (const NodeError& e) {
        log("Block processing error (NodeError): " + std::string(e.what()));
    } catch (const std::exception& e) {
        log("Unknown error processing block: " + std::string(e.what()));
    }
}

// محاكاة بث معاملة
void Node::broadcastTransaction(std::shared_ptr<Transaction> tx) {
    if (!allNetworkNodes) return; // لا يوجد شبكة للمحاكاة

    log("Broadcasting transaction: " + tx->getId().substr(0, 8) + "...");
    for (const auto& pair : *allNetworkNodes) {
        if (pair.first != nodeId) { // لا نرسل إلى أنفسنا
            // يمكن هنا استخدام خيوط منفصلة أو قائمة انتظار رسائل لمحاكاة أفضل
            // for simplicity, direct call
            pair.second->receiveTransaction(tx);
        }
    }
}

// محاكاة بث كتلة
void Node::broadcastBlock(std::shared_ptr<Block> block) {
    if (!allNetworkNodes) return; // لا يوجد شبكة للمحاكاة

    log("Broadcasting block: " + block->getHash().substr(0, 8) + "...");
    for (const auto& pair : *allNetworkNodes) {
        if (pair.first != nodeId) { // لا نرسل إلى أنفسنا
            // يمكن هنا استخدام خيوط منفصلة أو قائمة انتظار رسائل لمحاكاة أفضل
            // for simplicity, direct call
            pair.second->receiveBlock(block);
        }
    }
}

// محاولة اقتراح كتلة جديدة (إذا تم اختيار هذه العقدة كمدقق)
void Node::tryProposeBlock(std::int64_t currentTime) {
    // 1. التحقق مما إذا كانت هذه العقدة هي المدقق المختار
    std::string pickedValidatorId = validatorManager.pickValidator();
    if (pickedValidatorId != publicKey) {
        // log("Not picked as validator this round. Picked: " + pickedValidatorId.substr(0,8) + "...");
        return; // هذه العقدة لم يتم اختيارها لإنشاء كتلة
    }
    
    log("I (" + publicKey.substr(0, 8) + "...) was picked as validator!");

    // 2. جمع المعاملات من الـ DAG
    std::vector<std::string> tips = dag.getTips();
    std::vector<std::shared_ptr<Transaction>> transactionsToConfirm;
    
    // للحصول على معاملات، يمكننا اختيارها من الـ DAG بناءً على استراتيجية معينة
    // مثلاً، اختيار المعاملات التي لها أعلى عدد من الآباء أو الأبناء، أو الأقدم.
    // لتبسيط الأمر، سنختار بعض المعاملات "الطرفية" (tips) أو العشوائية من الـ DAG.
    // في نظام حقيقي، ستكون هناك استراتيجية أكثر تعقيداً لاختيار المعاملات (مثل المعاملات ذات الرسوم الأعلى).
    
    // يمكننا ببساطة أخذ بعض المعاملات من الـ DAG
    // iterate over all transactions in DAG (if not too large)
    std::vector<std::shared_ptr<Transaction>> allDagTransactions;
    for (const auto& pair : dag.transactions) { // accessing private member for simplicity, ideally through getter
        allDagTransactions.push_back(pair.second);
    }

    // فرز المعاملات (مثلاً، حسب الطابع الزمني - الأقدم أولاً)
    std::sort(allDagTransactions.begin(), allDagTransactions.end(), [](const std::shared_ptr<Transaction>& a, const std::shared_ptr<Transaction>& b) {
        return a->getTimestamp() < b->getTimestamp();
    });

    // اختيار ما يصل إلى `maxTransactionsPerBlock` معاملة
    for (size_t i = 0; i < allDagTransactions.size() && transactionsToConfirm.size() < maxTransactionsPerBlock; ++i) {
        transactionsToConfirm.push_back(allDagTransactions[i]);
    }

    if (transactionsToConfirm.empty()) {
        log("No transactions to confirm in DAG for block proposal.");
        return; // لا توجد معاملات لإنشاء كتلة بها
    }

    log("Proposing new block with " + std::to_string(transactionsToConfirm.size()) + " transactions.");

    // 3. إنشاء الكتلة الجديدة
    std::string prevBlockHash = finalityChain.getCurrentChainTipHash();
    if (prevBlockHash.empty() && finalityChain.getCurrentHeight() != -1) {
        // هذه حالة لا ينبغي أن تحدث إذا كان currentHeight مُداراً بشكل صحيح.
        // قد تحدث إذا كانت السلسلة فارغة ولم يتم تهيئة كتلة التكوين.
        log("Warning: Previous block hash is empty but chain is not at height -1.");
        // يمكن أن نُعيد تهيئة prevBlockHash ليكون كتلة التكوين الفارغة هنا.
        prevBlockHash = std::string(64, '0'); // أو التعامل معها بشكل صحيح.
    }
    
    std::shared_ptr<Block> newBlock = std::make_shared<Block>(
        prevBlockHash,
        publicKey,       // المدقق هو هذه العقدة
        privateKey,      // المفتاح الخاص للعقدة لتوقيع الكتلة
        transactionsToConfirm
    );

    // 4. معالجة الكتلة محلياً وبثها
    processIncomingBlock(newBlock); // ستضيفها إلى السلسلة وتزيل المعاملات من الـ DAG
    broadcastBlock(newBlock);       // تبث الكتلة الجديدة للشبكة
}

// محاكاة "تكة" (tick) في تشغيل العقدة
void Node::tick(std::int64_t currentTime) {
    // هذه الدالة تمثل دورة واحدة من عمل العقدة.
    // يمكن أن تتضمن:
    // 1. معالجة الرسائل المعلقة (إن وجدت، حالياً تتم المعالجة المباشرة في receiveX).
    // 2. محاولة اقتراح كتلة جديدة إذا كان هذا المدقق هو المختار.
    // 3. أي صيانة دورية أخرى (مثل تنظيف الـ DAG).

    try {
        // حاول اقتراح كتلة (إذا تم اختيار هذه العقدة كمدقق)
        tryProposeBlock(currentTime);
    } catch (const std::exception& e) {
        log("Error during tick (proposing block): " + std::string(e.what()));
    }
    
    // يمكن هنا إضافة منطق لتنظيف الـ DAG من المعاملات القديمة التي لم يتم تأكيدها لفترة طويلة.
}

// تسجيل العقدة كمدقق
void Node::registerAsValidator(double stakeAmount) {
    if (stakeAmount < minStakeAmount) {
        throw NodeError("Stake amount " + std::to_string(stakeAmount) + " is less than minimum required stake " + std::to_string(minStakeAmount));
    }
    validatorManager.registerValidator(publicKey, stakeAmount);
    log("Registered as validator with stake: " + std::to_string(stakeAmount));
}

// إلغاء تسجيل العقدة كمدقق
void Node::unregisterAsValidator() {
    validatorManager.removeValidator(publicKey);
    log("Unregistered as validator.");
}

// طباعة حالة العقدة
void Node::printNodeStatus() const {
    log("--- Node Status ---");
    log("ID: " + nodeId);
    log("Public Key: " + publicKey.substr(0, 8) + "...");
    log("Is validator: " + std::string(validatorManager.isActiveValidator(publicKey) ? "Yes" : "No"));
    if (validatorManager.isActiveValidator(publicKey)) {
        log("My Stake: " + std::to_string(validatorManager.getValidatorStake(publicKey)));
    }
    finalityChain.printChainStatus();
    dag.printDAGStatus();
    validatorManager.printValidators();
    log("--- End Node Status ---\n");
}

// مسح حالة العقدة
void Node::clear() {
    dag.clear();
    finalityChain.clear();
    validatorManager.clear();
    knownTransactions.clear();
    knownBlocks.clear();
    allNetworkNodes = nullptr; // إزالة مرجع الشبكة
    log("Node state cleared.");
}
