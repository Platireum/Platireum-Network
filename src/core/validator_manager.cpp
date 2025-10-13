#include "validator_manager.h" // We must include our own header file first
#include <iostream>            // For use in printing functions for debugging
#include <numeric>             // For using std::accumulate (not currently used but can be useful)

// --- Implementation of ValidatorManager class functions ---

// Constructor
ValidatorManager::ValidatorManager()
    // Initialize the random number generator using the current timestamp
    : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()),
      totalStake(0.0) {
    // Any other initialization can be added here
}

// Register a new validator or update the stake of an existing one
bool ValidatorManager::registerValidator(const std::string& publicKey, double amount) {
    if (publicKey.empty()) {
        throw ValidatorManagerError("Public key cannot be empty for validator registration.");
    }
    if (amount < 0) {
        throw ValidatorManagerError("Stake amount cannot be negative for validator registration.");
    }
    // A minimum stake can be set here (e.g., 100 coins)
    // if (amount < MIN_STAKE_AMOUNT) {
    //     throw ValidatorManagerError("Stake amount " + std::to_string(amount) + " is below minimum required stake.");
    // }

    auto it = activeValidators.find(publicKey);
    if (it != activeValidators.end()) {
        // If the validator already exists, update its stake
        double oldStake = it->second.stake;
        it->second.stake = amount;
        totalStake += (amount - oldStake); // Update the total stake
        std::cout << "Validator " << publicKey.substr(0, 8) << "... stake updated to " << amount << std::endl;
    } else {
        // If it's a new validator, add it
        activeValidators.emplace(publicKey, Validator(publicKey, amount));
        totalStake += amount; // Add the stake to the total sum
        std::cout << "Validator " << publicKey.substr(0, 8) << "... registered with stake " << amount << std::endl;
    }
    return true;
}

// Remove a validator
bool ValidatorManager::removeValidator(const std::string& publicKey) {
    auto it = activeValidators.find(publicKey);
    if (it != activeValidators.end()) {
        totalStake -= it->second.stake; // Deduct the validator's stake from the total sum
        activeValidators.erase(it);
        std::cout << "Validator " << publicKey.substr(0, 8) << "... removed." << std::endl;
        return true;
    }
    std::cerr << "Warning: Attempted to remove non-existent validator: " << publicKey.substr(0, 8) << "..." << std::endl;
    return false;
}

// Update the stake of an existing validator
void ValidatorManager::updateValidatorStake(const std::string& publicKey, double newAmount) {
    if (newAmount < 0) {
        throw ValidatorManagerError("New stake amount cannot be negative.");
    }

    auto it = activeValidators.find(publicKey);
    if (it == activeValidators.end()) {
        throw ValidatorManagerError("Validator not found for stake update: " + publicKey);
    }

    double oldStake = it->second.stake;
    it->second.stake = newAmount;
    totalStake += (newAmount - oldStake);
    std::cout << "Validator " << publicKey.substr(0, 8) << "... stake updated from " << oldStake << " to " << newAmount << std::endl;

    // Logic can be added here to remove the validator if its stake falls below the minimum
    // if (newAmount < MIN_STAKE_AMOUNT) {
    //     removeValidator(publicKey);
    //     std::cout << "Validator " << publicKey.substr(0, 8) << "... removed due to insufficient stake." << std::endl;
    // }
}

// Pick a validator based on their stake
std::string ValidatorManager::pickValidator() const {
    if (activeValidators.empty()) {
        throw ValidatorManagerError("No active validators to pick from.");
    }
    if (totalStake <= 0) {
        throw ValidatorManagerError("Total stake is zero or negative, cannot pick a validator.");
    }

    // Uniform random distribution to pick a point along the "stake bar"
    std::uniform_real_distribution<> dist(0.0, totalStake);
    double pick = dist(rng); // Pick a random number between 0 and the total stake

    double currentSum = 0.0;
    // Iterate through validators and add their stakes cumulatively until we reach the chosen point
    for (const auto& pair : activeValidators) {
        currentSum += pair.second.stake;
        if (pick <= currentSum) {
            return pair.first; // We found the validator!
        }
    }
    // This part should not be reached in a sane logic case
    throw ValidatorManagerError("Failed to pick a validator. This should not happen.");
}

// Check if the public key belongs to an active validator
bool ValidatorManager::isActiveValidator(const std::string& publicKey) const {
    return activeValidators.count(publicKey) > 0;
}

// Get the stake of a specific validator
double ValidatorManager::getValidatorStake(const std::string& publicKey) const {
    auto it = activeValidators.find(publicKey);
    if (it == activeValidators.end()) {
        throw ValidatorManagerError("Validator not found: " + publicKey);
    }
    return it->second.stake;
}

// Clear all validators
void ValidatorManager::clear() {
    activeValidators.clear();
    totalStake = 0.0;
    std::cout << "All validators cleared." << std::endl;
}

// Print the list of current validators
void ValidatorManager::printValidators() const {
    std::cout << "\n--- Active Validators Status ---" << std::endl;
    if (activeValidators.empty()) {
        std::cout << "No active validators." << std::endl;
    } else {
        for (const auto& pair : activeValidators) {
            std::cout << "  Validator ID: " << pair.first.substr(0, 10) << "..."
                      << " | Stake: " << std::fixed << std::setprecision(4) << pair.second.stake
                      << std::endl;
        }
    }
    std::cout << "Total Stake: " << std::fixed << std::setprecision(4) << totalStake << std::endl;
    std::cout << "Number of Validators: " << activeValidators.size() << std::endl;
    std::cout << "--- End Active Validators Status ---\n" << std::endl;
}
