#include "finality_chain.h"
#include <iostream>
#include <algorithm>

// Constructor
FinalityChain::FinalityChain(std::shared_ptr<ValidatorManager> vm) : currentHeight(-1), validatorManager(std::move(vm)) {
    // The genesis block will set the initial state
}

void FinalityChain::initializeGenesisBlock(const std::string& validatorId, const CryptoHelper::ECKeyPtr& validatorPrivateKey) {
    std::lock_guard<std::mutex> lock(chainMutex);

    if (currentHeight != -1) {
        throw FinalityChainError("Genesis block already initialized.");
    }

    // Create a dummy transaction for the genesis block (e.g., a coinbase transaction)
    // This transaction won't have parents in the DAG context.
    // For a coinbase, the payload will contain the output.
    json genesisPayload;
    genesisPayload["outputs"] = {{{"recipientPublicKey", validatorId}, {"amount", 1000000000000LL}}};

    Transaction genesisCoinbaseTx(
        TransactionType::VALUE_TRANSFER, // Type
        validatorId,                     // Creator Public Key
        genesisPayload.dump(),           // Payload (JSON string of outputs)
        {},                              // Parents
        {}                               // AI Proof
    );
    genesisCoinbaseTx.sign(validatorPrivateKey); // Sign with the validator's private key

    std::vector<std::shared_ptr<Transaction>> genesisTransactions;
    genesisTransactions.push_back(std::make_shared<Transaction>(genesisCoinbaseTx));

    // Create the genesis block
    Block genesisBlock("0000000000000000000000000000000000000000000000000000000000000000", // Previous block hash
                       0, // Height
                       "genesis_dag_root_hash", // Dummy DAG root hash
                       validatorId,
                       validatorPrivateKey,
                       genesisTransactions);

    // Add to blocks map
    blocks[genesisBlock.getHash()] = std::make_shared<Block>(genesisBlock);
    currentChainTipHash = genesisBlock.getHash();
    currentHeight = 0;
    blockHeights[genesisBlock.getHash()] = 0;
    hashByHeight[0] = genesisBlock.getHash();

    // Update UTXO set for genesis coinbase transaction
    for (size_t i = 0; i < genesisCoinbaseTx.getOutputs().size(); ++i) {
        utxoSet[genesisCoinbaseTx.getId() + ":" + std::to_string(i)] = genesisCoinbaseTx.getOutputs()[i];
    }

    std::cout << "Genesis block initialized with hash: " << currentChainTipHash.substr(0, 10) << "..." << std::endl;
}

bool FinalityChain::addBlock(std::shared_ptr<Block> newBlock,
                             const std::unordered_map<std::string, std::shared_ptr<Transaction>>& transactionsInBlock) {
    std::lock_guard<std::mutex> lock(chainMutex);

    if (!newBlock) {
        throw FinalityChainError("Attempted to add a null block.");
    }

    const std::string& blockHash = newBlock->getHash();
    const std::string& prevBlockHash = newBlock->getPreviousBlockHash();

    // 1. Check if block already exists
    if (blocks.count(blockHash)) {
        std::cerr << "Block already exists in chain: " << blockHash.substr(0, 10) << "..." << std::endl;
        return false;
    }

    // 2. Validate previous block existence and height
    auto prevBlockIt = blocks.find(prevBlockHash);
    if (prevBlockIt == blocks.end()) {
        std::cerr << "Previous block not found for block: " << blockHash.substr(0, 10) << "..." << std::endl;
        return false;
    }
    if (newBlock->getHeight() != prevBlockIt->second->getHeight() + 1) {
        std::cerr << "Block height mismatch for block: " << blockHash.substr(0, 10) << "..." << std::endl;
        return false;
    }

    // 3. Validate block (hash, signature, etc.)
    // In a real system, validatorPublicKeyHex would be retrieved from a staking registry
    // For now, we assume validatorId is the public key string itself.
    if (!newBlock->validate(newBlock->getValidatorId())) {
        std::cerr << "Block validation failed for block: " << blockHash.substr(0, 10) << "..." << std::endl;
        return false;
    }

    // 4. Temporarily apply UTXO changes to validate transactions
    std::unordered_map<std::string, TransactionOutput> tempUtxoSet = utxoSet;
    try {
        updateUtxoSet(*newBlock, transactionsInBlock, false, tempUtxoSet);
    } catch (const FinalityChainError& e) {
        std::cerr << "UTXO update failed for block " << blockHash.substr(0, 10) << "...: " << e.what() << std::endl;
        return false;
    }

    // If all validations pass, add the block to the chain
    blocks[blockHash] = newBlock;
    currentChainTipHash = blockHash;
    currentHeight = newBlock->getHeight();
    blockHeights[blockHash] = currentHeight;
    hashByHeight[currentHeight] = blockHash;
    utxoSet = tempUtxoSet; // Commit UTXO changes

    std::cout << "Block added: " << blockHash.substr(0, 10) << "... (Height: " << currentHeight << ")" << std::endl;
    return true;
}

std::shared_ptr<Block> FinalityChain::getBlock(const std::string& blockHash) const {
    std::lock_guard<std::mutex> lock(chainMutex);
    auto it = blocks.find(blockHash);
    if (it != blocks.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<Block> FinalityChain::getBlockByHeight(int height) const {
    std::lock_guard<std::mutex> lock(chainMutex);
    auto it = hashByHeight.find(height);
    if (it != hashByHeight.end()) {
        return getBlock(it->second);
    }
    return nullptr;
}







bool FinalityChain::containsTransaction(const std::string& txId) const {
    std::lock_guard<std::mutex> lock(chainMutex);
    for (const auto& pair : blocks) {
        const std::shared_ptr<Block>& block = pair.second;
        const std::vector<std::string>& txIds = block->getTransactionIds();
        if (std::find(txIds.begin(), txIds.end(), txId) != txIds.end()) {
            return true;
        }
    }
    return false;
}

bool FinalityChain::containsBlock(const std::string& blockHash) const {
    std::lock_guard<std::mutex> lock(chainMutex);
    return blocks.count(blockHash) > 0;
}

void FinalityChain::printChainStatus() const {
    std::lock_guard<std::mutex> lock(chainMutex);
    std::cout << "\n--- Finality Chain Status ---" << std::endl;
    std::cout << "Current Height: " << currentHeight << std::endl;
    if (!currentChainTipHash.empty()) {
        std::cout << "Current Tip Hash: " << currentChainTipHash.substr(0, 10) << "..." << std::endl;
    }
    std::cout << "Total Blocks: " << blocks.size() << std::endl;
    std::cout << "Total UTXOs: " << utxoSet.size() << std::endl;
    std::cout << "--- End Finality Chain Status ---\n" << std::endl;
}

void FinalityChain::clear() {
    std::lock_guard<std::mutex> lock(chainMutex);
    blocks.clear();
    utxoSet.clear();
    blockHeights.clear();
    hashByHeight.clear();
    currentChainTipHash = "";
    currentHeight = -1;
}



void FinalityChain::updateUtxoSet(const Block& block,
                                  const std::unordered_map<std::string, std::shared_ptr<Transaction>>& transactionsInBlock,
                                  bool isRevert,
                                  std::unordered_map<std::string, TransactionOutput>& targetUtxoSet) {
    for (const std::string& txId : block.getTransactionIds()) {
        auto txIt = transactionsInBlock.find(txId);
        if (txIt == transactionsInBlock.end()) {
            throw FinalityChainError("Transaction " + txId.substr(0, 10) + "... not found in block's provided transactions.");
        }
        const std::shared_ptr<Transaction>& tx = txIt->second;

        if (!isRevert) {
            // Apply transaction: remove spent UTXOs, add new ones
            for (const auto& input : tx->getInputs()) {
                std::string utxoKey = input.transactionId + ":" + std::to_string(input.outputIndex);
                if (targetUtxoSet.count(utxoKey)) {
                    targetUtxoSet.erase(utxoKey);
                } else {
                    throw FinalityChainError("Attempted to spend non-existent UTXO: " + utxoKey);
                }
            }
            for (size_t i = 0; i < tx->getOutputs().size(); ++i) {
                targetUtxoSet[tx->getId() + ":" + std::to_string(i)] = tx->getOutputs()[i];
            }
        } else {
            // Revert transaction: add back spent UTXOs, remove new ones
            for (const auto& input : tx->getInputs()) {
                std::string utxoKey = input.transactionId + ":" + std::to_string(input.outputIndex);
                // In revert, we add back the UTXO that was spent
                // This requires storing the state of UTXOs before the block was applied, or having access to previous blocks
                // For simplicity, this part assumes we can reconstruct the UTXO. More robust solution needed for reorgs.
                // For now, we'll just re-add a dummy if not found, or assume it's there.
                // A proper reorg mechanism would involve snapshotting UTXO sets or replaying from a common ancestor.
                // For this PoC, we'll assume a linear chain for now.
                // targetUtxoSet[utxoKey] = /* original UTXO */; // This is complex without full history
            }
            for (size_t i = 0; i < tx->getOutputs().size(); ++i) {
                targetUtxoSet.erase(tx->getId() + ":" + std::to_string(i));
            }
        }
    }
}

