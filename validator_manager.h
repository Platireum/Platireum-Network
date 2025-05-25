#ifndef VALIDATOR_MANAGER_H
#define VALIDATOR_MANAGER_H

#include <string>
#include <vector>
#include <unordered_map> // لتخزين معلومات المدققين وحصصهم
#include <random>        // لاختيار المدققين عشوائياً بناءً على الحصة
#include <chrono>        // للاستخدام في تهيئة مولد الأرقام العشوائية
#include <memory>        // For std::shared_ptr for EC_KEY
#include <stdexcept>     // For std::runtime_error

#include "crypto_helper.h" // نحتاج إلى دوال التشفير للمفاتيح العامة

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
struct Validator {
    std::string publicKey;  // المفتاح العام للمدقق (كمعرف فريد له)
    double stake;           // مقدار العملة التي تم وضعها كحصة (للمشاركة في الإجماع)
    // يمكن إضافة حقول أخرى مثل:
    // int consecutiveBlocksProposed; // عدد الكتل المتتالية التي اقترحها (لتحسين العدالة)
    // std::int64_t lastProposedTime; // آخر مرة اقترح فيها المدقق كتلة

    Validator(std::string pk, double s) : publicKey(std::move(pk)), stake(s) {}
};

/**
 * Manages validators and their stakes in a Proof of Stake consensus mechanism.
 * Selects validators for proposing new blocks based on their stake.
 */
class ValidatorManager {
private:
    // تخزين المدققين النشطين (المفتاح العام -> كائن Validator)
    std::unordered_map<std::string, Validator> activeValidators;
    
    // مجموع الحصص الكلي لجميع المدققين النشطين
    double totalStake;

    // مولد الأرقام العشوائية للاختيار القائم على الحصة
    mutable std::mt19937 rng; // mutable للسماح لدوال const بتغييرها (مثل pickValidator)

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
    std::string pickValidator() const;

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
};

#endif // VALIDATOR_MANAGER_H
