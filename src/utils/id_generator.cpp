#include "id_generator.h"
#include <chrono>
#include <random>

std::string generateUniqueId(const std::string& prefix) {
    auto now = std::chrono::high_resolution_clock::now();
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 999999);
    return prefix + "_" + std::to_string(nanoseconds) + "_" + std::to_string(distrib(gen));
}

