Text file: contract.h
Latest content with line numbers:
1	#ifndef SMART_CONTRACT_H
2	#define SMART_CONTRACT_H
3	
4	#include <string>
5	#include <vector>
6	#include <unordered_map>
7	#include <functional> // For std::function - might be removed if no longer needed
8	#include <memory>     // For std::shared_ptr
9	
10	// Forward declarations to break circular dependencies if needed later
11	// class Node; // If contract needs to interact directly with node's state
12	
13	/**
14	 * @brief Represents a simple Smart Contract in our simulated environment.
15	 * In a real blockchain, contracts have their own address, state, and bytecode.
16	 * Now we use actual WASM bytecode instead of symbolic names.
17	 */
18	class SmartContract {
19	private:
20	    std::string contractId; // Unique identifier for this contract (e.g., hash of deploy transaction)
21	    std::vector<uint8_t> contractBytecode; // The actual WASM bytecode of the contract (CHANGED)
22	    std::string ownerPublicKey; // Public key of the deployer
23	
24	    // A simplified state for the contract. In reality, this would be a Merkle Patricia Trie
25	    // or similar data structure persisted on chain.
26	    std::unordered_map<std::string, std::string> contractState;
27	
28	    // REMOVED: executionLogic callback - execution responsibility moved to VMEngine
29	
30	public:
31	    /**
32	     * @brief Constructor for SmartContract.
33	     * @param id Unique ID of the contract.
34	     * @param bytecode The contract's actual WASM bytecode.
35	     * @param owner The public key of the contract owner/deployer.
36	     */
37	    SmartContract(const std::string& id,
38	        const std::vector<uint8_t>& bytecode,
39	        const std::string& owner);
40	
41	    // Getters
42	    const std::string& getId() const { return contractId; }
43	    const std::string& getContractId() const { return contractId; }
44	    const std::vector<uint8_t>& getBytecode() const { return contractBytecode; } // CHANGED
45	    const std::string& getOwnerPublicKey() const { return ownerPublicKey; }
46	
47	    // State management for the contract (simplified)
48	    void setState(const std::string& key, const std::string& value);
49	    std::string getState(const std::string& key) const;
50	
51	    // REMOVED: setExecutionLogic method - execution logic is now embedded in bytecode
52	
53	    // REMOVED: execute method - execution responsibility moved to VMEngine
54	
55	    // Serialization/Deserialization (for persistence)
56	    // Note: These will need to handle binary bytecode (convert to/from Base64 for JSON storage)
57	    std::string serialize() const;
58	    static std::shared_ptr<SmartContract> deserialize(const std::string& data);
59	};
60	
61	#endif // SMART_CONTRACT_H
62	