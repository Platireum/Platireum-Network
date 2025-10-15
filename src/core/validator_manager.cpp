#include "validator_manager.h" 
#include <iostream>            
#include <numeric>             
#include <algorithm> // For std::remove_if

// --- Implementation of ValidatorManager class functions ---

// Constructor
ValidatorManager::ValidatorManager()
    // Initialize the random number generator using the current timestamp
    : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()),
      totalStake(0.0),
      totalComputeScore(0.0),
      schedule_index(0) {
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
        totalComputeScore -= it->second.compute_score; // Also deduct compute score
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
}

std::string ValidatorManager::pickValidator() {
    // Regenerate schedule if it\'s empty or exhausted
    if (validator_schedule.empty() || schedule_index >= validator_schedule.size()) {
        regenerate_schedule();
        schedule_index = 0; // Reset index for new schedule
    }

    // If after regeneration, the schedule is still empty, throw an error
    if (validator_schedule.empty()) {
        throw ValidatorManagerError("Validator schedule is empty, no eligible validators to pick.");
    }

    // Pick the next validator from the schedule
    std::string selected_validator = validator_schedule[schedule_index];
    schedule_index++;
    return selected_validator;
}

void ValidatorManager::regenerate_schedule() {
    validator_schedule.clear();
    if (activeValidators.empty()) {
        return;
    }

    // Calculate total power to normalize probabilities
    double total_power = 0.0;
    for (const auto& pair : activeValidators) {
        total_power += calculateValidatorPower(pair.first);
    }

    if (total_power <= 0) {
        // If total power is zero, no eligible validators, schedule remains empty
        return;
    }

    // Create a temporary list of validators, weighted by their power
    // For example, a validator with power 10 will appear 10 times in the list
    // This is a simplified approach for demonstration. A more efficient approach
    // would be to use a weighted random selection without explicitly duplicating entries.
    for (const auto& pair : activeValidators) {
        double power = calculateValidatorPower(pair.first);
        // Ensure power is at least 1 to be included in the schedule, or handle 0 power separately
        if (power > 0) {
            // The number of entries can be scaled to manage schedule size
            int entries = static_cast<int>(std::round(power / total_power * 100)); // Scale to 100 entries for example
            for (int i = 0; i < entries; ++i) {
                validator_schedule.push_back(pair.first);
            }
        }
    }

    // Shuffle the schedule to ensure fair distribution over time
    std::shuffle(validator_schedule.begin(), validator_schedule.end(), rng);
    std::cout << "Validator schedule regenerated with " << validator_schedule.size() << " entries." << std::endl;
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
    totalComputeScore = 0.0; // Clear compute score as well
    std::cout << "All validators cleared." << std::endl;
}

// Update compute score for a validator
void ValidatorManager::updateComputeScore(const std::string& publicKey, double score_increase) {
    if (score_increase < 0) {
        throw ValidatorManagerError("Compute score increase cannot be negative.");
    }

    auto it = activeValidators.find(publicKey);
    if (it == activeValidators.end()) {
        throw ValidatorManagerError("Validator not found for compute score update: " + publicKey);
    }

    it->second.compute_score += score_increase;
    totalComputeScore += score_increase;
    std::cout << "Validator " << publicKey.substr(0, 8) << "... compute score updated by " << score_increase
              << ", new score: " << it->second.compute_score << std::endl;
}

// Get compute score for a validator
double ValidatorManager::getValidatorComputeScore(const std::string& publicKey) const {
    auto it = activeValidators.find(publicKey);
    if (it == activeValidators.end()) {
        throw ValidatorManagerError("Validator not found: " + publicKey);
    }
    return it->second.compute_score;
}

// Calculate validator power
double ValidatorManager::calculateValidatorPower(const std::string& publicKey) const {
    auto it = activeValidators.find(publicKey);
    if (it == activeValidators.end()) {
        throw ValidatorManagerError("Validator not found: " + publicKey);
    }

    // Define minimum thresholds for a validator to be considered for selection
    const double MIN_STAKE_THRESHOLD = 100.0; // Example: minimum 100 units of stake
    const double MIN_COMPUTE_SCORE_THRESHOLD = 5.0; // Example: minimum 5 units of compute score

    // If a validator doesn't meet minimum requirements, their power is 0
    if (it->second.stake < MIN_STAKE_THRESHOLD) {
        return 0.0;
    }

    // Weights for combining stake and compute score
    // These could be dynamic or determined by governance in a more advanced system
    const double STAKE_WEIGHT = 0.5; 
    const double COMPUTE_SCORE_WEIGHT = 0.5;

    // Normalize stake and compute score relative to the maximum observed values or a predefined cap
    // Using totalStake and totalComputeScore for normalization as a starting point
    // In a real system, these might be normalized against network-wide averages or caps.
    // Define maximum possible values for normalization (can be dynamic or fixed based on network design)
    // Use a small epsilon to avoid division by zero if totalStake or totalComputeScore is zero
    double normalizedStake = (totalStake > 0) ? (it->second.stake / totalStake) : 0.0;
    double normalizedComputeScore = (totalComputeScore > 0) ? (it->second.compute_score / totalComputeScore) : 0.0;

    // If compute score is 0, give it a baseline to ensure it contributes to power if stake is sufficient
    if (it->second.compute_score == 0 && it->second.stake >= MIN_STAKE_THRESHOLD) {
        normalizedComputeScore = 0.01; // A small baseline to make it eligible
    }

    // Ensure normalized values are within [0, 1]
    normalizedStake = std::max(0.0, std::min(1.0, normalizedStake));
    normalizedComputeScore = std::max(0.0, std::min(1.0, normalizedComputeScore));

    // Combine normalized values using defined weights
    // This formula represents the 'value' a validator brings to the network.
    return (STAKE_WEIGHT * normalizedStake) + (COMPUTE_SCORE_WEIGHT * normalizedComputeScore);
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
                      << " | Compute Score: " << std::fixed << std::setprecision(4) << pair.second.compute_score
                      << std::endl;
        }
    }
    std::cout << "Total Stake: " << std::fixed << std::setprecision(4) << totalStake << std::endl;
    std::cout << "Total Compute Score: " << std::fixed << std::setprecision(4) << totalComputeScore << std::endl;
    std::cout << "Number of Validators: " << activeValidators.size() << std::endl;
    std::cout << "--- End Active Validators Status ---\n" << std::endl;
}

void ValidatorManager::addProvenWork(const ProvenWork& proof) {
    if (proof.score < 0) {
        throw ValidatorManagerError("Proven work score cannot be negative.");
    }

    auto it = activeValidators.find(proof.validator_id);
    if (it == activeValidators.end()) {
        throw ValidatorManagerError("Validator not found for proven work: " + proof.validator_id);
    }

    it->second.compute_score += proof.score;
    totalComputeScore += proof.score;
    std::cout << "Proven work added for validator " << proof.validator_id.substr(0, 8) << "... Score: " << proof.score
              << ", New total compute score: " << it->second.compute_score << std::endl;
}

