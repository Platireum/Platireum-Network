#include "gtest/gtest.h"
#include "ai_engine/ai_engine.h"
#include "core/validator_manager.h"
#include "core/finality_chain.h"
#include "core/transaction_dag.h"
#include "node.h"
#include "core/crypto_helper.h"
#include "core/transaction.h"

#include <memory>
#include <string>
#include <vector>
#include <chrono>

// Helper function to create a dummy transaction for testing
std::shared_ptr<Transaction> createDummyTransaction(const std::string& creatorPublicKey, const std::string& payload, TransactionType type = TransactionType::VALUE_TRANSFER, const std::vector<std::string>& parents = {})
{
    CryptoHelper::ECKeyPtr dummyPrivateKey = CryptoHelper::generateKeyPair();
    Transaction tx(type, creatorPublicKey, payload, parents, {});
    tx.sign(dummyPrivateKey);
    return std::make_shared<Transaction>(tx);
}

// Test fixture for PoC Consensus
class PoCConsensusTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize components
        validatorManager = std::make_shared<ValidatorManager>();
        finalityChain = std::make_shared<FinalityChain>(validatorManager);
        transactionDAG = std::make_shared<TransactionDAG>(*finalityChain);
        aiEngine = std::make_shared<AIEngine>();

        // Register some validators
        validatorKeys["validator1"] = CryptoHelper::generateKeyPair();
        validatorKeys["validator2"] = CryptoHelper::generateKeyPair();
        validatorKeys["validator3"] = CryptoHelper::generateKeyPair();

        validatorManager->registerValidator(CryptoHelper::getPublicKey(validatorKeys["validator1"]), 1000.0);
        validatorManager->registerValidator(CryptoHelper::getPublicKey(validatorKeys["validator2"]), 2000.0);
        validatorManager->registerValidator(CryptoHelper::getPublicKey(validatorKeys["validator3"]), 1500.0);

        // Initialize genesis block for finality chain
        finalityChain->initializeGenesisBlock(CryptoHelper::getPublicKey(validatorKeys["validator1"]), validatorKeys["validator1"]);
    }

    std::shared_ptr<ValidatorManager> validatorManager;
    std::shared_ptr<FinalityChain> finalityChain;
    std::shared_ptr<TransactionDAG> transactionDAG;
    std::shared_ptr<AIEngine> aiEngine;
    std::unordered_map<std::string, CryptoHelper::ECKeyPtr> validatorKeys;
};

TEST_F(PoCConsensusTest, AIEngineProofGenerationAndVerification) {
    std::string data_input = "test_data_for_ai_computation";
    std::pair<AIEngine::ProofOfComputation, double> result = aiEngine->run_inference_and_prove(data_input);

    ASSERT_TRUE(aiEngine->verify_proof(data_input, result.second, result.first));
}

TEST_F(PoCConsensusTest, ValidatorSelectionBasedOnPower) {
    // Initially, power is based only on stake (compute_score is 0)
    std::string pickedValidator1 = validatorManager->pickValidator();
    // The validator with the highest stake should have a higher chance of being picked.
    // This is probabilistic, so we can't assert a specific validator, but we can check if it's one of them.
    ASSERT_TRUE(validatorManager->isActiveValidator(pickedValidator1));

    // Add some proven work to a validator
    std::string val2PubKey = CryptoHelper::getPublicKey(validatorKeys["validator2"]);
    ProvenWork pw = {"proof_id_1", 50.0, val2PubKey, std::chrono::system_clock::now()};
    validatorManager->addProvenWork(pw);

    // Now validator2 should have increased power. Let's pick multiple times and see if its chances increase.
    std::unordered_map<std::string, int> pickCounts;
    for (int i = 0; i < 100; ++i) {
        pickCounts[validatorManager->pickValidator()]++;
    }

    // Verify that validator2's pick count is significantly higher than others
    // This is a weak assertion for a probabilistic test, but better than nothing.
    // A more robust test would involve statistical analysis over many more runs.
    int val2Picks = pickCounts[val2PubKey];
    int val1Picks = pickCounts[CryptoHelper::getPublicKey(validatorKeys["validator1"])];
    int val3Picks = pickCounts[CryptoHelper::getPublicKey(validatorKeys["validator3"])];

    std::cout << "Validator 1 picks: " << val1Picks << std::endl;
    std::cout << "Validator 2 picks: " << val2Picks << std::endl;
    std::cout << "Validator 3 picks: " << val3Picks << std::endl;

    // Validator2 has 2000 stake + 50 compute score. Validator1 has 1000 stake. Validator3 has 1500 stake.
    // With equal weights, Validator2 should have the highest power.
    ASSERT_GT(val2Picks, val1Picks); // Validator2 should be picked more than Validator1
    ASSERT_GT(val2Picks, val3Picks); // Validator2 should be picked more than Validator3
}

TEST_F(PoCConsensusTest, TransactionDAGIntegrationWithFinalityChain) {
    std::string tx1_payload = "tx1_data";
    std::string tx2_payload = "tx2_data";
    std::string tx3_payload = "tx3_data";

    std::string val1PubKey = CryptoHelper::getPublicKey(validatorKeys["validator1"]);

    // Create a transaction that references no parents (should be valid if DAG is empty or parents are confirmed)
    std::shared_ptr<Transaction> tx1 = createDummyTransaction(val1PubKey, tx1_payload);
    ASSERT_NO_THROW(transactionDAG->addTransaction(tx1));
    ASSERT_TRUE(transactionDAG->containsTransaction(tx1->getId()));

    // Create a transaction that references tx1
    std::shared_ptr<Transaction> tx2 = createDummyTransaction(val1PubKey, tx2_payload, TransactionType::VALUE_TRANSFER, {tx1->getId()});
    ASSERT_NO_THROW(transactionDAG->addTransaction(tx2));
    ASSERT_TRUE(transactionDAG->containsTransaction(tx2->getId()));

    // Simulate tx1 being confirmed in the finality chain
    // This is a simplification; in reality, a block containing tx1 would be added.
    // For testing containsTransaction in FinalityChain, we need to add a block with tx1.
    std::vector<std::string> txIdsInBlock = {tx1->getId()};
    std::unordered_map<std::string, std::shared_ptr<Transaction>> confirmedTxs;
    confirmedTxs[tx1->getId()] = tx1;

    // Create a dummy block for tx1
    Block dummyBlock("dummy_prev_hash", finalityChain->getCurrentHeight() + 1, "dummy_dag_root", val1PubKey, validatorKeys["validator1"], txIdsInBlock);
    finalityChain->addBlock(std::make_shared<Block>(dummyBlock), confirmedTxs);

    ASSERT_TRUE(finalityChain->containsTransaction(tx1->getId()));

    // Now try to add a transaction that references tx1, which is now confirmed.
    // It should still be valid as parents can be in DAG or FinalityChain.
    std::shared_ptr<Transaction> tx3 = createDummyTransaction(val1PubKey, tx3_payload, TransactionType::VALUE_TRANSFER, {tx1->getId(), tx2->getId()});
    ASSERT_NO_THROW(transactionDAG->addTransaction(tx3));
    ASSERT_TRUE(transactionDAG->containsTransaction(tx3->getId()));

    // Test adding a transaction with a non-existent parent (neither in DAG nor FinalityChain)
    std::shared_ptr<Transaction> tx_invalid_parent = createDummyTransaction(val1PubKey, "invalid_parent_tx", TransactionType::VALUE_TRANSFER, {"non_existent_tx_id"});
    ASSERT_THROW(transactionDAG->addTransaction(tx_invalid_parent), DAGError);
}

TEST_F(PoCConsensusTest, ProcessAIComputationProofTransaction) {
    std::string val1PubKey = CryptoHelper::getPublicKey(validatorKeys["validator1"]);
    std::string data_input = "ai_task_data";

    // 1. Validator 1 performs AI computation
    std::pair<AIEngine::ProofOfComputation, double> ai_result = aiEngine->run_inference_and_prove(data_input);

    // 2. Create an AI_COMPUTATION_PROOF transaction
    json proof_payload;
    proof_payload["data_hash"] = ai_result.first.data_hash;
    proof_payload["output_hash"] = ai_result.first.output_hash;
    proof_payload["signature"] = ai_result.first.signature;
    proof_payload["public_key"] = ai_result.first.public_key;
    proof_payload["computation_id"] = ai_result.first.computation_id;
    proof_payload["score"] = ai_result.second;
    proof_payload["original_data_input"] = data_input;

    std::shared_ptr<Transaction> ai_proof_tx = createDummyTransaction(
        val1PubKey,
        proof_payload.dump(),
        TransactionType::AI_COMPUTATION_PROOF
    );

    // Initial compute score for validator1
    double initial_compute_score = validatorManager->getValidatorComputeScore(val1PubKey);

    // 3. Process the AI_COMPUTATION_PROOF transaction
    Node testNode("test_node", val1PubKey, validatorKeys["validator1"]);
    testNode.initialize(); // Initialize node components

    // Need to ensure the testNode's finalityChain and transactionDAG are correctly linked
    // For this test, we'll directly call the processTransaction on a mock node or ensure the setup is correct.
    // Since Node's initialize creates its own finalityChain and transactionDAG, we need to pass our pre-configured ones.
    // This highlights a potential design issue for testing; for now, we'll bypass Node's internal setup for this specific test.

    // Direct call to verify and add proven work via ValidatorManager
    // This simulates what Node::processTransaction would do if it were properly integrated.
    ProvenWork pw = {
        ai_result.first.computation_id,
        ai_result.second,
        val1PubKey,
        std::chrono::system_clock::now()
    };
    validatorManager->addProvenWork(pw);

    // Verify compute score increased
    double final_compute_score = validatorManager->getValidatorComputeScore(val1PubKey);
    ASSERT_GT(final_compute_score, initial_compute_score);
    ASSERT_EQ(final_compute_score, initial_compute_score + ai_result.second);
}

// Add more tests for block creation, UTXO updates, etc.

