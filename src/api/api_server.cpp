#include "api_server.h"
#include <iostream>
#include <sstream>
#include <algorithm> // For std::remove
#include "../../src/node.h" // Include Node to interact with it
#include "../../src/core/transaction.h" // For Transaction serialization/deserialization
#include "../../src/core/finality_chain.h" // For Block serialization/deserialization
#include "../../src/smart_contracts/contract.h" // For SmartContract serialization/deserialization
#include "../../src/utils/json_utils.h" // For JSON utility functions

// --- Helper for simple JSON parsing (for contract parameters) ---
// This is a very rudimentary JSON parser. In a real-world scenario,
// use a robust JSON library like nlohmann/json.


// Helper to extract a parameter from a map, with a default value or throwing
std::string getParam(const std::unordered_map<std::string, std::string>& params, const std::string& key, bool required = false) {
    auto it = params.find(key);
    if (it != params.end()) {
        return it->second;
    }
    if (required) {
        throw ApiServerError("Missing required parameter: " + key);
    }
    return "";
}


// --- Implementation of ApiServer ---

ApiServer::ApiServer(const std::string& addr, int p, std::shared_ptr<Node> node)
    : address(addr), port(p), nodeInstance(node) {
    if (!nodeInstance) {
        throw ApiServerError("ApiServer initialized with a null Node instance.");
    }
}

void ApiServer::log(const std::string& message) const {
    std::cout << "[API Server " << address << ":" << port << "] " << message << std::endl;
}

// --- API Endpoint Handlers ---

ApiResponse ApiServer::handleGetNodeInfo(const ApiRequest& req) {
    // Example: Return basic node information
    // In a real scenario, Node would have a method like getNodeStatus()
    std::unordered_map<std::string, std::string> info;
    info["node_id"] = nodeInstance->getNodeId();
    info["network_status"] = "connected"; // Simplified
    info["chain_tip_hash"] = nodeInstance->getChainTipHash();
    info["chain_tip_height"] = std::to_string(nodeInstance->getChainTipHeight());
    info["pending_transactions"] = std::to_string(nodeInstance->getPendingTransactionsCount());
    info["node_balance"] = std::to_string(nodeInstance->getAccountBalance(nodeInstance->getNodeId())); // Get node's own balance

    return ApiResponse::success(createSimpleJson(info));
}

ApiResponse ApiServer::handlePostTransaction(const ApiRequest& req) {
    try {
        // Assume req.body contains a serialized transaction JSON
        std::shared_ptr<Transaction> tx = Transaction::deserialize(req.body);
        
        // Broadcast the transaction through the node's network layer
        nodeInstance->broadcastTransaction(tx);
        
        std::unordered_map<std::string, std::string> response_data;
        response_data["status"] = "Transaction received and broadcasted.";
        response_data["tx_id"] = tx->getId();
        return ApiResponse::success(createSimpleJson(response_data));

    } catch (const std::exception& e) {
        return ApiResponse::error(400, "Invalid transaction data: " + std::string(e.what()));
    }
}

ApiResponse ApiServer::handleGetBlock(const ApiRequest& req) {
    try {
        std::string blockHash = getParam(req.params, "hash", true); // Get block hash from params
        
        std::shared_ptr<Block> block = nodeInstance->getBlockByHash(blockHash);
        if (block) {
            return ApiResponse::success(block->serialize());
        } else {
            return ApiResponse::error(404, "Block not found: " + blockHash);
        }
    } catch (const ApiServerError& e) {
        return ApiResponse::error(400, e.what());
    } catch (const std::exception& e) {
        return ApiResponse::error(500, "Error getting block: " + std::string(e.what()));
    }
}

ApiResponse ApiServer::handleMineBlock(const ApiRequest& req) {
    // This endpoint is for demonstration/testing only; real blockchains don't expose mining via API
    try {
        std::string minterId = nodeInstance->getNodeId(); // Assume the API call is to mine for this node
        // You might optionally allow minterId to be passed in body for testing other validators
        // auto params = parseSimpleJson(req.body);
        // if (params.count("minter_id")) minterId = params["minter_id"];

        std::shared_ptr<Block> minedBlock = nodeInstance->mineBlock(minterId); // Call node's mineBlock method
        if (minedBlock) {
            std::unordered_map<std::string, std::string> response_data;
            response_data["status"] = "Block mined successfully!";
            response_data["block_hash"] = minedBlock->getHash();
            response_data["block_height"] = std::to_string(minedBlock->getHeight());
            return ApiResponse::success(createSimpleJson(response_data));
        } else {
            return ApiResponse::error(500, "Failed to mine block.");
        }
    } catch (const std::exception& e) {
        return ApiResponse::error(500, "Mining error: " + std::string(e.what()));
    }
}

ApiResponse ApiServer::handleGetBlockchainState(const ApiRequest& req) {
    // Return a simplified view of the blockchain's current state
    // This could be UTXO count, number of deployed contracts, etc.
    std::unordered_map<std::string, std::string> state;
    state["utxo_count"] = std::to_string(nodeInstance->getUtxoSetCount());
    state["deployed_contracts_count"] = std::to_string(nodeInstance->getDeployedContractsCount());

    return ApiResponse::success(createSimpleJson(state));
}

ApiResponse ApiServer::handlePostDeployContract(const ApiRequest& req) {
    try {
        // The body should contain the serialized SmartContract object
        std::shared_ptr<SmartContract> contract = SmartContract::deserialize(req.body);
        nodeInstance->deployContract(contract, contract->getBytecode()); // Node will handle the actual deployment via VM
        
        std::unordered_map<std::string, std::string> response_data;
        response_data["status"] = "Contract deployment initiated.";
        response_data["contract_id"] = contract->getId();
        return ApiResponse::success(createSimpleJson(response_data));

    } catch (const std::exception& e) {
        return ApiResponse::error(400, "Invalid contract data or deployment failed: " + std::string(e.what()));
    }
}

ApiResponse ApiServer::handlePostCallContract(const ApiRequest& req) {
    try {
        // Request body structure for contract call (example):
        // { "contract_id": "...", "sender_id": "...", "method_name": "...", "params_json": "{...}" }
        // We'll use a simple parser for this
        auto params = parseSimpleJson(req.body); // Use the simple JSON parser

        std::string contractId = getParam(params, "contract_id", true);
        std::string senderId = getParam(params, "sender_id", true);
        std::string methodName = getParam(params, "method_name", true);
        std::string paramsJson = getParam(params, "params_json", false); // Optional for some calls

        std::string result = nodeInstance->callContract(contractId, senderId, methodName, paramsJson);

        std::unordered_map<std::string, std::string> response_data;
        response_data["status"] = "Contract call successful.";
        response_data["result"] = result;
        return ApiResponse::success(createSimpleJson(response_data));

    } catch (const ApiServerError& e) {
        return ApiResponse::error(400, e.what());
    } catch (const std::exception& e) {
        return ApiResponse::error(500, "Contract call failed: " + std::string(e.what()));
    }
}

// --- Initialization and Request Processing ---

void ApiServer::initialize() {
    // Register GET handlers
    getHandlers["/node/info"] = std::bind(&ApiServer::handleGetNodeInfo, this, std::placeholders::_1);
    getHandlers["/block/{hash}"] = std::bind(&ApiServer::handleGetBlock, this, std::placeholders::_1);
    getHandlers["/blockchain/state"] = std::bind(&ApiServer::handleGetBlockchainState, this, std::placeholders::_1);

    // Register POST handlers
    postHandlers["/transaction"] = std::bind(&ApiServer::handlePostTransaction, this, std::placeholders::_1);
    postHandlers["/mine"] = std::bind(&ApiServer::handleMineBlock, this, std::placeholders::_1); // For testing only!
    postHandlers["/contract/deploy"] = std::bind(&ApiServer::handlePostDeployContract, this, std::placeholders::_1);
    postHandlers["/contract/call"] = std::bind(&ApiServer::handlePostCallContract, this, std::placeholders::_1);

    log("API Server initialized. Listening on " + address + ":" + std::to_string(port));
}

void ApiServer::start() {
    log("API Server started. Ready to process requests.");
    // In a real server, this would involve blocking operations to listen for connections.
    // For our simulation, it's just a placeholder.
}

ApiResponse ApiServer::processRequest(const ApiRequest& request) {
    log("Processing " + request.method + " request for endpoint: " + request.endpoint);

    // Basic routing logic
    if (request.method == "GET") {
        for (const auto& pair : getHandlers) {
            // Simple path matching. For real APIs, use regex or dedicated routing libraries.
            // Handles /block/{hash} case
            if (pair.first.find("{hash}") != std::string::npos) {
                std::string base_path = pair.first.substr(0, pair.first.find("{hash}"));
                if (request.endpoint.rfind(base_path, 0) == 0) { // Check if endpoint starts with base_path
                    std::string hash = request.endpoint.substr(base_path.length());
                    ApiRequest new_req = request; // Copy request to modify params
                    new_req.params["hash"] = hash;
                    return pair.second(new_req);
                }
            } else if (request.endpoint == pair.first) {
                return pair.second(request);
            }
        }
    } else if (request.method == "POST") {
        for (const auto& pair : postHandlers) {
            if (request.endpoint == pair.first) {
                return pair.second(request);
            }
        }
    }
    
    // If no handler found
    log("No handler found for " + request.method + " " + request.endpoint);
    return ApiResponse::error(404, "Endpoint not found: " + request.endpoint);
}

void ApiServer::stop() {
    log("API Server stopped.");
}