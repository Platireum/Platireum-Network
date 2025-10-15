#ifndef VALIDATOR_MANAGER_H
#define VALIDATOR_MANAGER_H

#include <string>
#include <vector>
#include <unordered_map> // For storing validator information and their stakes
#include <random>        // For randomly selecting validators based on stake
#include <chrono>        // For use in initializing the random number generator
#include <memory>        // For std::shared_ptr for EC_KEY
#include <stdexcept>     // For std::runtime_error

#include "crypto_helper.h" // We need crypto functions for public keys

// ---------------------------
// 0. Error Handling
// ---------------------------
/**
 * Custom exception class for ValidatorManager-specific errors.
 */
class ValidatorManagerError : public std::runtime_error {
public:
    explicit ValidatorManagerError(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------
// 5. Validator Management (Proof of Stake)
// ---------------------------

/**
 * Represents a Validator in the Proof of Stake system.
 * Stores their public key (ID) and their staked amount.
 */
struct ProvenWork {
    std::string proof_id;      // Unique ID for the proof of computation
    double score;              // Score assigned to the computation
    std::string validator_id;  // ID of the validator who submitted the proof
    std::chrono::system_clock::time_point timestamp; // Time of submission
};

struct Validator {
    std::string publicKey;  // The validator's public key (as its unique identifier)
    double stake;           // The amount of currency staked (for consensus participation)
    double compute_score;   // New: To track useful computational work performed
    // Other fields can be added, such as:
    // int consecutiveBlocksProposed; // Number of consecutive blocks proposed (to improve fairness)
    // std::int64_t lastProposedTime; // Last time the validator proposed a block

    Validator(std::string pk, double s) : publicKey(std::move(pk)), stake(s), compute_score(0.0) {}
};

/**
 * Manages validators and their stakes in a Proof of Stake consensus mechanism.
 * Selects validators for proposing new blocks based on their stake.
 */
class ValidatorManager {
private:
    // Stores active validators (public key -> Validator object)
    std::unordered_map<std::string, Validator> activeValidators;
    
    // The total stake of all active validators
    double totalStake;
    double totalComputeScore; // New: To track the total compute score of all active validators

    // Random number generator for stake-based selection
    mutable std::mt19937 rng; // mutable to allow const functions to change it (like pickValidator)

    // For Value-Based Selection
    std::vector<std::string> validator_schedule;
    mutable size_t schedule_index;

    void regenerate_schedule();

public:
    // Constructor
    ValidatorManager();

    /**
     * Registers a new validator or updates an existing validator's stake.
     * @param publicKey The public key (ID) of the validator.
     * @param amount The amount to stake.
     * @return True if successful, false if amount is invalid.
     * @throws ValidatorManagerError if public key is empty or amount is negative.
     */
    bool registerValidator(const std::string& publicKey, double amount);

    /**
     * Removes a validator (e.g., if their stake falls below a threshold or they exit).
     * @param publicKey The public key (ID) of the validator to remove.
     * @return True if validator was removed, false if not found.
     */
    bool removeValidator(const std::string& publicKey);

    /**
     * Updates an existing validator's stake.
     * @param publicKey The public key (ID) of the validator.
     * @param newAmount The new total stake amount for the validator.
     * @throws ValidatorManagerError if validator not found or newAmount is negative.
     */
    void updateValidatorStake(const std::string& publicKey, double newAmount);

    /**
     * Selects a validator based on their stake for proposing the next block.
     * The higher the stake, the higher the probability of selection.
     * @return The public key of the selected validator.
     * @throws ValidatorManagerError if no active validators are registered.
     */
    std::string pickValidator();

    /**
     * Checks if a public key belongs to an active validator.
     * @param publicKey The public key to check.
     * @return True if active, false otherwise.
     */
    bool isActiveValidator(const std::string& publicKey) const;

    /**
     * Gets the stake amount for a given validator.
     * @param publicKey The public key of the validator.
     * @return The stake amount.
     * @throws ValidatorManagerError if validator not found.
     */
    double getValidatorStake(const std::string& publicKey) const;

    /**
     * Returns the total combined stake of all active validators.
     */
    double getTotalStake() const { return totalStake; }

    /**
     * Returns the number of active validators.
     */
    size_t getValidatorCount() const { return activeValidators.size(); }

    // Utility/Debugging methods
    void printValidators() const;
    void clear(); // Clears all validators (for testing/reset)

    /**
     * @brief Updates the compute score for a given validator.
     * @param publicKey The public key (ID) of the validator.
     * @param score_increase The amount to add to the compute score.
     * @throws ValidatorManagerError if validator not found or score_increase is negative.
     */
    void updateComputeScore(const std::string& publicKey, double score_increase);

    /**
     * @brief Calculates the total power of a validator based on stake and compute score.
     * @param publicKey The public key (ID) of the validator.
     * @return The calculated validator power.
     * @throws ValidatorManagerError if validator not found.
     */
    double calculateValidatorPower(const std::string& publicKey) const;

    // Getters for compute score (optional, but good for debugging/monitoring)
    double getValidatorComputeScore(const std::string& publicKey) const;

    // Getter for all active validators (for iteration/debugging)
    const std::unordered_map<std::string, Validator>& getValidators() const { return activeValidators; }

    /**
     * @brief Adds a new proof of useful work to the system.
     * @param proof The proven work to add.
     */
    void addProvenWork(const ProvenWork& proof);
};

#endif // VALIDATOR_MANAGER_H
