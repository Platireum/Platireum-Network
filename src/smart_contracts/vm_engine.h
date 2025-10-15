Text file: vm_engine.h
Latest content with line numbers:
1	#ifndef VM_ENGINE_H
2	#define VM_ENGINE_H
3	
4	#include <string>
5	#include <memory>         // For std::shared_ptr
6	#include <unordered_map>  // To manage deployed contracts
7	#include <stdexcept>      // For custom exceptions
8	#include <functional>     // For std::function (for any remaining utility callbacks)
9	
10	// Include necessary headers from our project structure
11	#include "contract.h" // For SmartContract class
12	
13	// Forward declaration for parseSimpleJson
14	std::unordered_map<std::string, std::string> parseSimpleJson(const std::string& jsonString);
15	
16	// Includes for WASM runtime, e.g., Wasmer
17	// #include "wasmer.h" // Temporarily disabled for compilation
18	
19	// Forward declarations if VMEngine needs to hold pointers to Node components
20	// This avoids circular dependencies and keeps the VM layer cleaner.
21	class Transaction; // To pass contract-related transactions
22	class FinalityChain; // To access blockchain state like UTXO set
23	class TransactionDAG; // To access DAG state
24	
25	// --- 0. Error Handling ---
26	/**
27	 * @brief Custom exception class for VMEngine-specific errors.
28	 */
29	class VMEngineError : public std::runtime_error {
30	public:
31	    explicit VMEngineError(const std::string& msg) : std::runtime_error(msg) {}
32	};
33	
34	// --- 1. VMEngine Class ---
35	/**
36	 * @brief A Virtual Machine (VM) Engine for executing WASM-based smart contracts.
37	 *
38	 * This VM uses a WASM runtime (e.g., Wasmer) to execute contract bytecode in a secure,
39	 * sandboxed environment. It manages deployed contracts and their state, and provides
40	 * an execution environment with host functions for blockchain interactions.
41	 *
42	 * The engine handles WASM module compilation, instantiation, and execution while
43	 * providing controlled access to blockchain resources through host functions.
44	 */
45	class VMEngine {
46	private:
47	    // Store deployed contracts by their ID
48	    std::unordered_map<std::string, std::shared_ptr<SmartContract>> deployedContracts;
49	
50	    // WASM Runtime Components (new)
51	    // Using unique_ptr with custom deleters to ensure proper resource cleanup
52	//    std::unique_ptr<wasm_engine_t, decltype(&wasm_engine_delete)> wasmEngine; // Temporarily disabled
53	//    std::unique_ptr<wasm_store_t, decltype(&wasm_store_delete)> wasmStore; // Temporarily disabled
54	
55	    // Store WASM instances for deployed contracts
56	    // Contract ID -> WASM instance
57	//    std::unordered_map<std::string, std::unique_ptr<wasm_instance_t, decltype(&wasm_instance_delete)>> wasmInstances; // Temporarily disabled
58	
59	    // Private helper for internal logging
60	    void log(const std::string& message) const;
61	
62	    /**
63	     * @brief Compiles and instantiates a WASM module from bytecode.
64	     * This replaces the old bindContractLogic method.
65	     * @param contractId The ID of the contract being deployed.
66	     * @param wasmBytecode The WASM bytecode to compile and instantiate.
67	     * @throws VMEngineError if compilation or instantiation fails.
68	     */
69	//    void instantiateWASMModule(const std::string& contractId, const std::vector<uint8_t>& wasmBytecode); // Temporarily disabled
70	
71	    /**
72	     * @brief Defines host functions that contracts can call to interact with the blockchain.
73	     * These functions replace the old callback system with a more secure, sandboxed approach.
74	     * @param imports The imports object to which host functions will be added.
75	     */
76	//    void setupHostFunctions(wasm_importtype_vec_t* imports); // Temporarily disabled
77	
78	public:
79	    VMEngine(); // Constructor
80	    ~VMEngine(); // Destructor for proper WASM resource cleanup
81	
82	    /**
83	     * @brief Deploys a new smart contract to the VM with WASM bytecode.
84	     * This compiles and instantiates the WASM module for the contract.
85	     * @param contract A shared_ptr to the SmartContract object to deploy.
86	     * @param wasmBytecode The WASM bytecode of the contract.
87	     * @throws VMEngineError if a contract with the same ID already exists or WASM instantiation fails.
88	     */
89	    void deployContract(std::shared_ptr<SmartContract> contract, const std::vector<uint8_t>& wasmBytecode);
90	
91	    /**
92	     * @brief Executes a function within a deployed smart contract using WASM.
93	     * This function is the primary entry point for contract interactions.
94	     * @param contractId The ID of the contract to execute.
95	     * @param senderId The public key of the account calling the contract (e.g., from a transaction).
96	     * @param methodName The name of the method/function to call within the contract.
97	     * @param paramsJson A JSON string containing parameters for the method.
98	     * @return A string representing the result of the execution.
99	     * @throws VMEngineError if the contract is not found or WASM execution fails.
100	     */
101	    std::string executeContract(const std::string& contractId,
102	        const std::string& senderId,
103	        const std::string& methodName,
104	        const std::string& paramsJson);
105	
106	    /**
107	     * @brief Retrieves a deployed smart contract by its ID.
108	     * @param contractId The ID of the contract to retrieve.
109	     * @return A shared_ptr to the SmartContract, or nullptr if not found.
110	     */
111	    std::shared_ptr<SmartContract> getContract(const std::string& contractId) const;
112	
113	    /**
114	     * @brief Checks if a contract with the given ID is deployed.
115	     * @param contractId The ID of the contract to check.
116	     * @return True if the contract is deployed, false otherwise.
117	     */
118	    bool hasContract(const std::string& contractId) const;
119	
120	    /**
121	     * @brief Gets the WASM instance for a specific contract.
122	     * @param contractId The ID of the contract.
123	     * @return Pointer to the WASM instance, or nullptr if not found.
124	     */
125	//    wasm_instance_t* getWASMInstance(const std::string& contractId) const; // Temporarily disabled
126	
127	    // --- Persistence (for saving/loading deployed contracts) ---
128	    // These functions would interact with the StorageManager.
129	    // They are typically managed by the Node/Blockchain, not VM directly.
130	    // However, the VM needs to provide a way to load contracts.
131	
132	    /**
133	     * @brief Loads deployed contracts from persistent storage (e.g., via StorageManager).
134	     * This would typically be called during node startup and would need to reinstantiate WASM modules.
135	     * @param contractMap The map of contracts to load into the VM.
136	     * @param wasmBytecodeProvider A function that provides WASM bytecode for a given contract ID.
137	     */
138	    void loadDeployedContracts(
139	        const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& contractMap,
140	        std::function<std::vector<uint8_t>(const std::string&)> wasmBytecodeProvider);
141	
142	    /**
143	     * @brief Returns a map of all currently deployed contracts.
144	     * Useful for persisting the VM state (e.g., to StorageManager).
145	     */
146	    const std::unordered_map<std::string, std::shared_ptr<SmartContract>>& getAllDeployedContracts() const {
147	        return deployedContracts;
148	    }
149	
150	    // Note: The old callback setters (setOnTransferFundsCallback, setOnGetBalanceCallback) 
151	    // have been removed. Blockchain interactions are now handled through host functions
152	    // that are set up during WASM module instantiation, providing a more secure and
153	    // sandboxed environment for contract execution.
154	};
155	
156	#endif // VM_ENGINE_H
157	