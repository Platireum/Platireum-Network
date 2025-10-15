#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <string>
#include <unordered_map>
#include <sstream>
#include <algorithm>

// Helper for simple JSON parsing (for contract parameters)
std::unordered_map<std::string, std::string> parseSimpleJson(const std::string& jsonString);

// Helper for simple JSON creation (for API responses)
std::string createSimpleJson(const std::unordered_map<std::string, std::string>& data);

#endif // JSON_UTILS_H

