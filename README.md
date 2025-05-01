# Platireum-Network-
Overview
This system combines blockchain security with Directed Acyclic Graph (DAG) scalability to create a high-performance distributed ledger. Key features include:

Proof-of-Stake consensus

UTXO model similar to Bitcoin

Fast DAG-based transaction processing

Periodic blockchain finality

Smart contract support

Core Components
1. CryptoHelper Class
Handles all cryptographic operations using OpenSSL:

Key generation (ECDSA secp256k1)

Digital signatures

SHA-256 hashing

Public key management

Key Methods:

generateKeyPair(): Creates new public/private key pair

signData(): Signs messages with private key

verifySignature(): Verifies message signatures

sha256(): Computes SHA-256 hash

2. Transaction System
Implements Unspent Transaction Output (UTXO) model:

TransactionOutput:

Represents unspent coins

Contains: txId, outputIndex, ownerAddress, amount

TransactionInput:

References UTXO being spent

Contains: utxoId, signature, publicKey

Transaction:

Combines inputs and outputs

Validates against UTXO set

Includes DAG parent references

Generates unique hash ID

3. TransactionDAG Class
Manages the DAG structure:

Stores all transactions

Tracks parent-child relationships

Maintains current "tips" (transactions with no children)

Updates UTXO set

Provides thread-safe access

Key Methods:

addTransaction(): Validates and adds new transaction

getTips(): Returns current tips for new transactions

getAddressUTXOs(): Returns UTXOs for specific address

4. FinalityChain Class
Provides blockchain finality:

Creates periodic blocks from DAG tips

Maintains block chain

Provides block lookup methods

Block Structure:

blockNumber, blockHash, previousHash

transactions list, validator, timestamp

5. ValidatorManager Class
Manages proof-of-stake validators:

Tracks validator stakes

Selects validators weighted by stake

Manages validator keys

Thread-safe operations

6. HybridLedger Class
Main system combining all components:

Coordinates DAG and blockchain

Manages validator selection

Handles block creation thread

Provides public API for:

Submitting transactions

Querying state

Validator operations

Workflow
Transaction Creation:

User creates transaction spending UTXOs

Signs inputs with private key

Selects parent transactions from DAG tips

Transaction Processing:

Transaction added to DAG

Validated against UTXO set

Updates DAG structure and tips

Block Creation (every 30 seconds):

Select validator based on stake

Create block from current DAG tips

Add block to finality chain

Update validator information

Validation:

All transactions cryptographically verified

UTXO existence and ownership checked

No double spends allowed

Error Handling
Custom exception classes:

CryptoError: Cryptographic operations

TransactionError: Invalid transactions

LedgerError: System-level issues

All errors include descriptive messages and context.

Thread Safety
Critical sections protected by:

std::mutex for exclusive access

std::lock_guard for RAII locking

Atomic flags for control variables

Dependencies
OpenSSL (crypto, ec, ecdsa, sha)

C++17 standard library

Usage Example
Initialize system:
HybridLedger ledger;
auto key = CryptoHelper::generateKeyPair();
ledger.addValidator("alice", std::move(key), 5000.0);

Create transaction:
auto utxos = ledger.getUTXOs("alice");
Transaction tx = createTransaction(utxos, "bob", 100.0);
ledger.submitTransaction(tx);

System runs automatically:

Processes transactions into DAG

Creates finality blocks periodically

Notes
System designed for high throughput

Configurable block interval

Extensible for different consensus rules

Production-ready error handling
