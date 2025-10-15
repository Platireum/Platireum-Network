# Implementation Notes: Proof of Computing

## 1\. Merging the "Compute Provider" and "Validator" Roles

[cite\_start]**Answer:** There should be a logical separation between the two roles, but they are to be executed by a single entity (the Node) for it to become a fully qualified validator[cite: 5]. [cite\_start]In other words, for your node to become a "Validator," it must first prove itself as an active and reliable "Compute Provider"[cite: 6].

**Proposed Code Modifications:**

1.  [cite\_start]**Extend the Validator Struct:** In `src/core/validator_manager.h`, we will expand the `Validator` struct to include a metric for completed work[cite: 7].

    ```cpp
    // In file: src/core/validator_manager.h
    struct Validator {
        std::string publicKey;
        double stake;
        double compute_score; // <-- New addition: to track useful work done
        // ... any other fields like last proposed time

        Validator(std::string pk, double s) : publicKey(std::move(pk)), stake(s), compute_score(0.0) {}
    };
    ```

2.  [cite\_start]**Add a "Compute Unit" to the Node:** In `src/node.h`, the `Node` will be responsible for running the computation logic (like the `AIEngine` we discussed)[cite: 10]. This programmatically separates responsibilities; [cite\_start]`ValidatorManager` tracks the results, while the `Node` (via `AIEngine`) performs the work[cite: 11].

-----

## 2\. Modifications to Implement "Proven Useful Work"

**Answer:** You will need to add a new module to define "useful work" and modify the transaction system to record it.

**Key Components for Modification:**

1.  **Create AIEngine:**

      * [cite\_start]Create a new directory `src/ai_engine/` with files `ai_engine.h` and `ai_engine.cpp`[cite: 13].
      * This component will contain the actual computational functions. [cite\_start]To start, it could be a simple function like `run_inference(data)` that uses a pre-trained ONNX model[cite: 14].

2.  **Expand Transaction Types:**

      * [cite\_start]In `src/core/transaction.h`, add new types to the `TransactionType` enum to enable the computation lifecycle[cite: 15].

    <!-- end list -->

    ```cpp
    // In file: src/core/transaction.h
    enum class TransactionType {
        // ... existing types
        AI_COMPUTATION_PROOF, // Transaction submitted by a worker to prove work completion
        // ...
    };
    ```

3.  **Update ValidatorManager:**

      * [cite\_start]Add a new function in `src/core/validator_manager.cpp` called `update_compute_score`[cite: 17].
      * [cite\_start]When the network receives a valid `AI_COMPUTATION_PROOF` transaction, this function is called to increase the `compute_score` of the validator who submitted the proof[cite: 17].

-----

## 3\. Calculating "Validator Power"

**Answer:** It will be calculated as a weighted average that combines capital and work. [cite\_start]This ensures both factors are important[cite: 19].

**Proposed Formula:**
`Validator Power = (α * NormalizedStake) + (β * NormalizedComputeScore)`

  * [cite\_start]**α (alpha) & β (beta):** These are weighting coefficients (numbers between 0 and 1, summing to 1)[cite: 19]. [cite\_start]These values are determined by network governance[cite: 20].
      * [cite\_start]Example: `α = 0.4` and `β = 0.6` means useful work has more weight (60%) than capital (40%)[cite: 20].
  * [cite\_start]**NormalizedStake:** The validator's share of the total staked capital (`validator.stake / total_stake_in_network`)[cite: 21].
  * [cite\_start]**NormalizedComputeScore:** The validator's share of the total compute points (`validator.compute_score / total_compute_score_in_network`)[cite: 22].

[cite\_start]**Code Location:** A new function called `calculate_validator_power(publicKey)` should be added inside `src/core/validator_manager.cpp`[cite: 22].

-----

## 4\. Modifying the Validator Selection Mechanism

[cite\_start]**Answer:** We will modify the existing `pickValidator` function to use "Validator Power" instead of relying solely on "Stake"[cite: 23].

**Proposed Code Modifications:**

[cite\_start]The current `pickValidator` function in `src/core/validator_manager.cpp` selects based on `totalStake`[cite: 24]. We will modify it as follows:

```cpp
// In file: src/core/validator_manager.cpp (modifying pickValidator logic)
std::string ValidatorManager::pickValidator() const {
    if (activeValidators.empty()) {
        throw ValidatorManagerError("No active validators to pick from.");
    }

    // 1. Calculate total validator power instead of total stake
    double total_power = 0.0;
    for (const auto& pair : activeValidators) {
        total_power += calculate_validator_power(pair.first); // Use the new function
    }

    if (total_power <= 0) {
        // ... error handling
    }

    // 2. Random selection based on total power
    std::uniform_real_distribution<> dist(0.0, total_power);
    double pick = dist(rng);

    // 3. Select the validator whose "power" falls within the chosen point
    double currentSum = 0.0;
    for (const auto& pair : activeValidators) {
        currentSum += calculate_validator_power(pair.first);
        if (pick <= currentSum) {
            return pair.first;
        }
    }
    // ...
}
```

-----

## 5\. Required Changes in DAG and Blockchain Structure

**Answer:** The good news is that the current architecture does not require radical structural changes. You have designed it correctly from the start. `TransactionDAG` and `FinalityChain` are exactly what is needed. [cite\_start]The changes will be logical, not structural[cite: 33].

  * **TransactionDAG (`src/core/transaction_dag.h`):**

      * [cite\_start]No structural change is required[cite: 34]. It will continue to act as a fast ingestion layer. [cite\_start]It will now receive `AI_COMPUTATION_PROOF` transactions just as it receives any other transaction, which proves the design's robustness[cite: 35].

  * **FinalityChain (`src/core/finality_chain.h`):**

      * [cite\_start]No structural change is required[cite: 36]. It will continue to function as the final settlement layer.
      * **Logical Change:** The logic for "selecting transactions" from the DAG to be included in a new block will be influenced by the PoC mechanism. [cite\_start]The validator selected (based on Validator Power) will be the one to perform this task[cite: 37, 38].

-----

## Transaction Prioritization Mechanisms

The core idea is to create a "layered system" for transactions, where not all transactions are treated equally. [cite\_start]An urgent financial transfer transaction has a higher priority than a "compute proof" that can wait a few minutes[cite: 39]. To achieve this, we can integrate two main mechanisms into the Platireum protocol:

### 1\. Dual Fee Market

This is the economic incentive-based solution. Instead of a single transaction fee, fees are split into two parts:

  * **a. Base Fee:**

      * [cite\_start]**What is it?** A low, fixed fee that everyone pays to get their transaction included in the `TransactionDAG`[cite: 42]. [cite\_start]This fee covers the basic cost of processing and ingesting the transaction into the network[cite: 43].
      * [cite\_start]**Its purpose:** To ensure that "compute proof" transactions and other non-urgent transactions can enter the network at a very low and predictable cost[cite: 44].

  * **b. Priority Fee:**

      * [cite\_start]**What is it?** An optional "tip" that a user can add to their transaction[cite: 45].
      * **Its purpose:** To signal to Validators that this transaction is urgent. [cite\_start]When a validator creates a new block on the `FinalityChain`, it will scan the DAG and select transactions with the highest "priority fees" first, as this maximizes its profits[cite: 46].

**How this solves the problem:**

  * **Compute Proof Transaction:** A "compute provider" can send their proof with a priority fee of zero. Their transaction will enter the DAG immediately and wait until it's its turn to be included in a `FinalityChain` block. [cite\_start]This is perfectly acceptable since the payment confirmation is not instant[cite: 48, 49].
  * **Urgent Financial Transaction:** A user wanting a fast transfer can add a small priority fee (even fractions of a cent). [cite\_start]This will make their transaction "jump the queue" and be selected by validators in the very next block, ensuring quick final settlement[cite: 50].

### 2\. Block Quotas

This is the protocol-rule-based solution to ensure fairness and prevent one type of transaction from dominating the network.

  * [cite\_start]**The Core Idea:** A protocol-level rule is enforced, stating that every block created on the `FinalityChain` must allocate a portion of its space to different transaction types[cite: 52].
  * [cite\_start]**How it works in your project:** We can define a rule that **25% of each block's space is exclusively reserved for financial transactions** (of type `VALUE_TRANSFER`)[cite: 53].
  * [cite\_start]When a validator creates a new block, it first fills this 25% of space with the financial transactions from the DAG that have the highest "priority fees"[cite: 54].
  * [cite\_start]Only then does it use the remaining 75% of the space to include any other type of transaction, such as "compute proofs"[cite: 55].

**How this solves the problem:**

  * [cite\_start]**Prevents Starvation:** This mechanism guarantees that even if there are millions of compute proof transactions offering high priority fees, financial transactions will always have a "reserved seat" in every block[cite: 56].
  * [cite\_start]**Creates Specialized Lanes:** It's like having a dedicated lane for buses and ambulances on a highway, ensuring they always reach their destination quickly, regardless of how congested the other lanes are[cite: 57].

### Conclusion

By combining these two mechanisms, the Platireum network creates a sophisticated and flexible transaction management system:

  * The **Dual Fee Market** provides economic flexibility and allows the market to determine transaction priority.
  * [cite\_start]**Block Quotas** provide a protocol-level safety net to ensure the network's core functions are never marginalized[cite: 59].
