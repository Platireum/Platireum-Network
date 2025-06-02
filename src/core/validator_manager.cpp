#include "validator_manager.h" // يجب تضمين ملف الرأس الخاص بنا أولاً
#include <iostream>            // للاستخدام في دوال الطباعة لتصحيح الأخطاء
#include <numeric>             // لاستخدام std::accumulate (ليس مستخدماً حالياً ولكن يمكن أن يكون مفيداً)

// --- تنفيذ دوال فئة ValidatorManager ---

// Constructor
ValidatorManager::ValidatorManager()
    // تهيئة مولد الأرقام العشوائية باستخدام الطابع الزمني الحالي
    : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()),
      totalStake(0.0) {
    // يمكن إضافة أي تهيئة أخرى هنا
}

// تسجيل مدقق جديد أو تحديث حصة مدقق موجود
bool ValidatorManager::registerValidator(const std::string& publicKey, double amount) {
    if (publicKey.empty()) {
        throw ValidatorManagerError("Public key cannot be empty for validator registration.");
    }
    if (amount < 0) {
        throw ValidatorManagerError("Stake amount cannot be negative for validator registration.");
    }
    // يمكن هنا وضع حد أدنى للحصة (مثلاً، 100 عملة)
    // if (amount < MIN_STAKE_AMOUNT) {
    //     throw ValidatorManagerError("Stake amount " + std::to_string(amount) + " is below minimum required stake.");
    // }

    auto it = activeValidators.find(publicKey);
    if (it != activeValidators.end()) {
        // إذا كان المدقق موجوداً بالفعل، قم بتحديث حصته
        double oldStake = it->second.stake;
        it->second.stake = amount;
        totalStake += (amount - oldStake); // تحديث مجموع الحصص الكلي
        std::cout << "Validator " << publicKey.substr(0, 8) << "... stake updated to " << amount << std::endl;
    } else {
        // إذا كان مدققاً جديداً، قم بإضافته
        activeValidators.emplace(publicKey, Validator(publicKey, amount));
        totalStake += amount; // إضافة الحصة إلى المجموع الكلي
        std::cout << "Validator " << publicKey.substr(0, 8) << "... registered with stake " << amount << std::endl;
    }
    return true;
}

// إزالة مدقق
bool ValidatorManager::removeValidator(const std::string& publicKey) {
    auto it = activeValidators.find(publicKey);
    if (it != activeValidators.end()) {
        totalStake -= it->second.stake; // خصم حصة المدقق من المجموع الكلي
        activeValidators.erase(it);
        std::cout << "Validator " << publicKey.substr(0, 8) << "... removed." << std::endl;
        return true;
    }
    std::cerr << "Warning: Attempted to remove non-existent validator: " << publicKey.substr(0, 8) << "..." << std::endl;
    return false;
}

// تحديث حصة مدقق موجود
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

    // يمكن هنا إضافة منطق لإزالة المدقق إذا انخفضت حصته عن الحد الأدنى
    // if (newAmount < MIN_STAKE_AMOUNT) {
    //     removeValidator(publicKey);
    //     std::cout << "Validator " << publicKey.substr(0, 8) << "... removed due to insufficient stake." << std::endl;
    // }
}

// اختيار مدقق بناءً على حصته
std::string ValidatorManager::pickValidator() const {
    if (activeValidators.empty()) {
        throw ValidatorManagerError("No active validators to pick from.");
    }
    if (totalStake <= 0) {
        throw ValidatorManagerError("Total stake is zero or negative, cannot pick a validator.");
    }

    // توزيع عشوائي موحد (uniform distribution) لاختيار نقطة على طول "شريط" الحصص
    std::uniform_real_distribution<> dist(0.0, totalStake);
    double pick = dist(rng); // اختر رقماً عشوائياً بين 0 والمجموع الكلي للحصص

    double currentSum = 0.0;
    // المرور على المدققين وإضافة حصصهم بشكل تراكمي حتى نصل إلى النقطة المختارة
    for (const auto& pair : activeValidators) {
        currentSum += pair.second.stake;
        if (pick <= currentSum) {
            return pair.first; // لقد وجدنا المدقق!
        }
    }
    // هذا الجزء لا يجب أن يتم الوصول إليه في حالة المنطق السليم
    throw ValidatorManagerError("Failed to pick a validator. This should not happen.");
}

// التحقق مما إذا كان المفتاح العام ينتمي إلى مدقق نشط
bool ValidatorManager::isActiveValidator(const std::string& publicKey) const {
    return activeValidators.count(publicKey) > 0;
}

// جلب حصة مدقق معين
double ValidatorManager::getValidatorStake(const std::string& publicKey) const {
    auto it = activeValidators.find(publicKey);
    if (it == activeValidators.end()) {
        throw ValidatorManagerError("Validator not found: " + publicKey);
    }
    return it->second.stake;
}

// مسح جميع المدققين
void ValidatorManager::clear() {
    activeValidators.clear();
    totalStake = 0.0;
    std::cout << "All validators cleared." << std::endl;
}

// طباعة قائمة المدققين الحاليين
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
