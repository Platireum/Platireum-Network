Text file: block.h
Latest content with line numbers:
1	#ifndef BLOCK_H
2	#define BLOCK_H
3	
4	#include <string>
5	#include <vector>
6	#include <memory>
7	#include <chrono>
8	#include <numeric>
9	#include <algorithm>
10	#include <stdexcept>
11	#include <sstream>
12	#include <iomanip>
13	
14	#include "crypto_helper.h"
15	#include "transaction.h"
16	
17	/**
18	 * @brief Represents a block in the Finality Chain.
19	 * Each block contains a hash, previous block hash, Merkle root of transactions,
20	 * timestamp, validator ID, and a list of transaction IDs.
21	 */
22	class Block {
23	private:
24	    std::string hash;               // Hash of this block
25	    std::string previousBlockHash;  // Hash of the previous block
26	    int height;                     // Block height (number of blocks before this one)
27	    std::string dagRootHash;        // Merkle root of all transactions in the DAG at the time of block creation
28	    long long timestamp;            // Unix timestamp of block creation
29	    std::string validatorId;        // ID of the validator who created this block
30	    std::string validatorSignature; // Signature of the validator on the block hash
31	    std::vector<std::string> transactionIds; // IDs of transactions included in this block
32	
33	    // Helper to calculate the block's hash
34	    void calculateHash();
35	
36	public:
37	    // Constructor for creating a new block (used by validator/miner)
38	        Block(std::string previousBlockHash,
39	          int height,
40	          std::string dagRootHash,
41	          std::string validatorId,
42	          const CryptoHelper::ECKeyPtr& validatorPrivateKey,
43	          const std::vector<std::shared_ptr<Transaction>>& confirmedTransactions);
44	
45	    // Constructor for deserializing or recreating an existing block
46	    Block(std::string hash,
47	          std::string previousBlockHash,
48	          int height,
49	          std::string dagRoot,
50	          long long ts,
51	          std::string valId,
52	          std::string valSignature,
53	          const std::vector<std::string>& txIds);
54	
55	    // Validate the block (hash, signature, transactions, etc.)
56	    bool validate(const std::string& validatorPublicKeyHex) const;
57	
58	    // Sign the block with the validator's private key
59	    void sign(const CryptoHelper::ECKeyPtr& privateKey);
60	
61	    // --- Getters ---
62	    const std::string& getHash() const { return hash; }
63	    const std::string& getPreviousBlockHash() const { return previousBlockHash; }
64	    int getHeight() const { return height; }
65	    const std::string& getDagRootHash() const { return dagRootHash; }
66	    long long getTimestamp() const { return timestamp; }
67	    const std::string& getValidatorId() const { return validatorId; }
68	    const std::string& getValidatorSignature() const { return validatorSignature; }
69	    const std::vector<std::string>& getTransactionIds() const { return transactionIds; }
70	
71	    // Serializes the block data to a JSON string
72	    std::string serialize() const;
73	
74	    // Deserializes a JSON string into a Block object
75	    static std::shared_ptr<Block> deserialize(const std::string& jsonString);
76	
77	    // Provides a human-readable string representation of the block
78	    std::string toString() const;
79	};
80	
81	#endif // BLOCK_H
82	
83	