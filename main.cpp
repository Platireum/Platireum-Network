#include <iostream>
#include <vector>
#include <string>
#include <memory>       // For std::shared_ptr
#include <thread>       // For std::this_thread::sleep_for
#include <chrono>       // For std::chrono
#include <map>          // To store nodes by ID, shared among them
#include <stdexcept>    // For catching exceptions

// Include all our custom headers
#include "crypto_helper.h"
#include "transaction.h"
#include "transaction_dag.h"
#include "finality_chain.h"
#include "validator_manager.h"
#include "node.h"

// Helper function to convert a double to a fixed-precision string
std::string to_fixed_string(double value, int precision = 8) {
    std::stringstream ss;
    ss << std::fixed << std::setprecision(precision) << value;
    return ss.str();
}

int main() {
    std::cout << "Starting Blockchain-DAG Hybrid Simulation...\n" << std::endl;

    // --- 1. Setup Network and Nodes ---
    // A shared map to simulate the network of nodes.
    // Each node needs to be able to "send" transactions/blocks to other nodes.
    // Using a map for easy lookup by nodeId.
    auto allNetworkNodes = std::make_shared<std::unordered_map<std::string, std::shared_ptr<Node>>>();

    // Create several nodes
    std::vector<std::shared_ptr<Node>> nodes;
    
    // Node A (Genesis Node & Initial Validator)
    std::string nodeA_id = "Node_A";
    auto nodeA = std::make_shared<Node>(nodeA_id, 100.0, 5); // Min stake 100, Max Tx per block 5
    nodes.push_back(nodeA);
    (*allNetworkNodes)[nodeA_id] = nodeA;

    // Node B
    std::string nodeB_id = "Node_B";
    auto nodeB = std::make_shared<Node>(nodeB_id, 100.0, 5);
    nodes.push_back(nodeB);
    (*allNetworkNodes)[nodeB_id] = nodeB;

    // Node C
    std::string nodeC_id = "Node_C";
    auto nodeC = std::make_shared<Node>(nodeC_id, 100.0, 5);
    nodes.push_back(nodeC);
    (*allNetworkNodes)[nodeC_id] = nodeC;

    // --- 2. Initialize Nodes ---
    // Initialize Node A as the genesis node
    nodeA->initialize(true, allNetworkNodes);
    // Initialize other nodes (they will sync with Node A's genesis block)
    nodeB->initialize(false, allNetworkNodes);
    nodeC->initialize(false, allNetworkNodes);
    
    std::cout << "\n--- Initializing Nodes ---\n" << std::endl;
    nodeA->printNodeStatus();
    nodeB->printNodeStatus();
    nodeC->printNodeStatus();

    // --- 3. Register Validators ---
    // All nodes register as validators to participate in block proposal
    double validator_stake = 500.0; // Example stake amount
    try {
        nodeA->registerAsValidator(validator_stake);
        nodeB->registerAsValidator(validator_stake);
        nodeC->registerAsValidator(validator_stake);
    } catch (const NodeError& e) {
        std::cerr << "Validator registration failed: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\n--- Validators Registered ---\n" << std::endl;
    nodeA->getValidatorManager().printValidators(); // Print validators from one node's perspective (should be same for all)

    // --- 4. Simulate Transaction Creation and Broadcast ---
    std::cout << "\n--- Simulating Transactions ---\n" << std::endl;
    
    // Get UTXO for Node A (genesis node has initial funds)
    // Note: The genesis block creation in FinalityChain::initializeGenesisBlock()
    // needs to ensure that the genesis validator (Node A) receives an initial UTXO.
    // For this simulation, we'll manually create a UTXO for Node A if FinalityChain didn't.
    // In a real system, the genesis block would include a coinbase transaction
    // that creates the initial supply and assigns it to the genesis validator.
    
    // Let's assume Node A's public key now owns a UTXO from the genesis block coinbase.
    // We'll manually create a mock UTXO for Node A to enable sending transactions.
    // This is a temporary hack until genesis block coinbase logic is fully in FinalityChain.
    std::string nodeA_pubKey = nodeA->getPublicKey();
    TransactionOutput nodeA_initial_utxo("genesis_txid_for_A", 0, nodeA_pubKey, 1000000.0); // Mock UTXO for Node A
    // Add this mock UTXO to Node A's UTXO set directly for testing purposes.
    // In a real system, this should be handled by the FinalityChain's genesis logic.
    // It's not ideal to access private members like this, but for simulation it works.
    const_cast<FinalityChain&>(nodeA->getFinalityChain()).utxoSet[nodeA_initial_utxo.getId()] = nodeA_initial_utxo;
    nodeA->log("Manually added mock initial UTXO to Node A's UTXO set for testing: " + to_fixed_string(nodeA_initial_utxo.amount));


    std::shared_ptr<Transaction> tx1, tx2, tx3;

    try {
        // Node A sends funds to Node B
        tx1 = nodeA->createAndSendTransaction(
            nodeA->privateKey,
            nodeB->getPublicKey(),
            10.0,
            {nodeA_initial_utxo} // Using the initial UTXO for Node A
        );
        // After this, Node A's initial UTXO is spent, and new UTXOs are created (10.0 to B, change to A)
        // We need to keep track of Node A's change UTXO for subsequent transactions.
        
        // Find Node A's new UTXO (the change from tx1)
        // This is complex as UTXOs are identified by txid:output_index.
        // For simplicity, we'll assume the change output is the second one created.
        // In reality, you'd iterate through the new transactions outputs or UTXO set.
        TransactionOutput tx1_nodeA_change_utxo;
        bool found_change = false;
        if (tx1->getOutputs().size() > 1 && tx1->getOutputs()[1].owner == nodeA_pubKey) {
            tx1_nodeA_change_utxo = tx1->getOutputs()[1];
            found_change = true;
            nodeA->log("Found Node A's change UTXO from TX1: " + tx1_nodeA_change_utxo.getId());
        } else {
            nodeA->log("Warning: Could not easily find Node A's change UTXO from TX1.");
            // For now, let's just make another mock UTXO for node A for next tx, this is fragile.
            // A better way is to retrieve the UTXO set after the first transaction.
            const_cast<FinalityChain&>(nodeA->getFinalityChain()).utxoSet.clear(); // Clear to re-add correct ones later
            // After tx1, the UTXO set should reflect: tx1's outputs.
            // Let's manually add a mock one for node A for next tx.
            nodeA_initial_utxo = TransactionOutput("mock_txid_A_2", 0, nodeA_pubKey, 999980.0); // Simulate change
            const_cast<FinalityChain&>(nodeA->getFinalityChain()).utxoSet[nodeA_initial_utxo.getId()] = nodeA_initial_utxo;
        }

        // Node B sends funds to Node C (using the UTXO received from Node A)
        // We need Node B's newly acquired UTXO from tx1
        TransactionOutput tx1_nodeB_utxo = tx1->getOutputs()[0]; // Assuming first output is to Node B

        tx2 = nodeB->createAndSendTransaction(
            nodeB->privateKey,
            nodeC->getPublicKey(),
            5.0,
            {tx1_nodeB_utxo} // Using the UTXO received from Node A
        );

        // Node C sends funds back to Node A (using the UTXO received from Node B)
        // We need Node C's newly acquired UTXO from tx2
        TransactionOutput tx2_nodeC_utxo = tx2->getOutputs()[0]; // Assuming first output is to Node C

        tx3 = nodeC->createAndSendTransaction(
            nodeC->privateKey,
            nodeA->getPublicKey(),
            2.0,
            {tx2_nodeC_utxo} // Using the UTXO received from Node B
        );

    } catch (const NodeError& e) {
        std::cerr << "Transaction creation failed: " << e.what() << std::endl;
        // Continue simulation even if one transaction fails for demonstration
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred during transaction creation: " << e.what() << std::endl;
    }


    // --- 5. Simulate Network Ticks and Block Proposals ---
    std::cout << "\n--- Simulating Network Ticks and Block Proposals ---\n" << std::endl;

    int num_ticks = 10; // Number of simulation steps
    for (int i = 0; i < num_ticks; ++i) {
        std::cout << "\n----- TICK " << i + 1 << " -----\n" << std::endl;
        std::int64_t currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()
                                    ).count();

        // Each node takes a "tick"
        for (const auto& node_ptr : nodes) {
            try {
                node_ptr->tick(currentTime);
            } catch (const std::exception& e) {
                std::cerr << "[Error in Node " << node_ptr->getNodeId() << " tick]: " << e.what() << std::endl;
            }
        }

        // Give some time for simulated propagation (optional in this simple model)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // --- 6. Final Status Check ---
    std::cout << "\n--- Final Network Status ---\n" << std::endl;
    for (const auto& node_ptr : nodes) {
        node_ptr->printNodeStatus();
    }
    
    std::cout << "\nSimulation Finished." << std::endl;

    return 0;
}
