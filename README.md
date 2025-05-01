## Overview

This system architecture integrates the security of blockchain technology with the scalability of a Directed Acyclic Graph (DAG) to establish a high-performance distributed ledger. Key features include a Proof-of-Stake consensus mechanism, a UTXO model akin to Bitcoin, rapid DAG-based transaction processing, periodic blockchain finality, and support for smart contracts.

## Core Components

### 1. CryptoHelper Class

This class encapsulates all cryptographic operations utilizing the OpenSSL library. Its functionalities encompass:

* **Key generation (ECDSA secp256k1)**: Generation of Elliptic Curve Digital Signature Algorithm key pairs using the secp256k1 curve.
* **Digital signatures**: Creation of digital signatures for transaction authentication.
* **SHA-256 hashing**: Computation of Secure Hash Algorithm 256-bit digests for data integrity.
* **Public key management**: Handling and storage of public keys.

**Key Methods:**

* `generateKeyPair()`: Generates a new public/private key pair.
* `signData()`: Signs a given message using the private key.
* `verifySignature()`: Verifies the digital signature of a message.
* `sha256()`: Computes the SHA-256 hash of input data.

### 2. Transaction System

This module implements the Unspent Transaction Output (UTXO) model.

* **TransactionOutput**: Represents an unspent coin and contains the following attributes:
    * `txId`: Identifier of the transaction that created this output.
    * `outputIndex`: Index of this output within the creating transaction.
    * `ownerAddress`: The public address of the output owner.
    * `amount`: The value of the unspent coin.
* **TransactionInput**: References a UTXO being spent and includes:
    * `utxoId`: Identifier of the UTXO being consumed.
    * `signature`: Digital signature proving ownership of the UTXO.
    * `publicKey`: The public key associated with the private key used for signing.
* **Transaction**: Combines transaction inputs and outputs. It undergoes validation against the current UTXO set, incorporates references to parent transactions within the DAG, and generates a unique hash identifier.

### 3. TransactionDAG Class

This class manages the Directed Acyclic Graph (DAG) structure, responsible for:

* Storing all transactions within the DAG.
* Tracking the parent-child relationships between transactions.
* Maintaining a set of current "tips" – transactions with no subsequent child transactions.
* Updating the UTXO set based on processed transactions.
* Providing thread-safe access to the DAG data.

**Key Methods:**

* `addTransaction()`: Validates a new transaction and adds it to the DAG.
* `getTips()`: Returns the current set of tip transactions.
* `getAddressUTXOs()`: Retrieves all unspent transaction outputs associated with a specific address.

### 4. FinalityChain Class

This component ensures blockchain-level finality for the transactions within the DAG. It functions by:

* Creating periodic blocks composed of the current DAG tips.
* Maintaining the sequential blockchain of these finality blocks.
* Providing methods for looking up blocks within the chain.

**Block Structure:**

* `blockNumber`: Sequential identifier of the block.
* `blockHash`: Unique hash of the current block.
* `previousHash`: Hash of the preceding block in the chain.
* `transactions`: List of transaction hashes finalized in this block.
* `validator`: The validator who proposed this block.
* `timestamp`: Time at which the block was created.

### 5. ValidatorManager Class

This class manages the network's Proof-of-Stake validators, including:

* Tracking the stake amount for each validator.
* Selecting validators for block creation based on their staked weight.
* Managing the public keys of the validators.
* Ensuring thread-safe operations for validator data.

### 6. HybridLedger Class

This is the central system component that integrates all other modules. It is responsible for:

* Coordinating the operation of the DAG and the finality blockchain.
* Managing the selection of validators for block creation.
* Handling the background thread responsible for periodic block creation.
* Providing a public API for interacting with the ledger, including:
    * Submitting new transactions to the DAG.
    * Querying the current state of the ledger.
    * Performing validator-related operations.

## Workflow

### Transaction Creation

1.  A user initiates a transaction, specifying the UTXOs they wish to spend.
2.  The user signs the transaction inputs using their private key, proving ownership of the UTXOs.
3.  The user selects one or more recent tip transactions from the DAG to serve as parent transactions for the new transaction.

### Transaction Processing

1.  The newly created transaction is added to the TransactionDAG.
2.  The transaction is validated against the current UTXO set to ensure the inputs are valid and unspent.
3.  The DAG structure is updated to include the new transaction and its parent-child relationships.
4.  The set of DAG tips is updated accordingly.

### Block Creation (Periodic)

1.  At a configured interval (e.g., every 30 seconds), a validator is selected based on their stake in the system.
2.  The selected validator proposes a new block containing the current set of DAG tip transactions.
3.  The new block is added to the FinalityChain, referencing the previous block's hash.
4.  Validator-related information (e.g., rewards) may be updated.

### Validation

* All transactions within the DAG are cryptographically verified using the signatures provided in the inputs.
* The existence and ownership of the UTXOs being spent are checked against the current UTXO set.
* Mechanisms are in place to prevent double-spending of UTXOs.

## Error Handling

The system incorporates custom exception classes to handle specific error conditions:

* `CryptoError`: Indicates errors during cryptographic operations.
* `TransactionError`: Signifies invalid or malformed transactions.
* `LedgerError`: Represents system-level issues and inconsistencies.

All custom exception classes include descriptive error messages and contextual information to aid in debugging and issue resolution.

## Thread Safety

Critical sections of the code that involve shared data structures are protected using:

* `std::mutex` for ensuring exclusive access to shared resources.
* `std::lock_guard` for Resource Acquisition Is Initialization (RAII)-style locking, automatically releasing the lock when the guard goes out of scope.
* Atomic flags for managing the state of control variables in a thread-safe manner.

## Dependencies

The system relies on the following external libraries and standards:

* **OpenSSL**: Used for all cryptographic operations (including `crypto`, `ec`, `ecdsa`, and `sha`).
* **C++17 Standard Library**: Utilized for various core functionalities and data structures.
