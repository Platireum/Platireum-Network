#include "json_utils.h"

// --- Helper for simple JSON parsing (for contract parameters) ---
// This is a very rudimentary JSON parser. In a real-world scenario,
// use a robust JSON library like nlohmann/json.
std::unordered_map<std::string, std::string> parseSimpleJson(const std::string& jsonString) {
    std::unordered_map<std::string, std::string> params;
    if (jsonString.empty() || jsonString == "{}") {
        return params;
    }

    std::string cleanJson = jsonString;
    // Remove outer braces if present
    if (cleanJson.front() == '{' && cleanJson.back() == '}') {
        cleanJson = cleanJson.substr(1, cleanJson.length() - 2);
    }

    std::stringstream ss(cleanJson);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        size_t colonPos = segment.find(':');
        if (colonPos == std::string::npos) {
            continue; // Invalid segment
        }

        std::string key = segment.substr(0, colonPos);
        std::string value = segment.substr(colonPos + 1);

        // Trim whitespace and remove quotes
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        if (key.length() >= 2 && key.front() == '"' && key.back() == '"') {
            key = key.substr(1, key.length() - 2);
        }

        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.length() - 2);
        }

        params[key] = value;
    }
    return params;
}


// --- Helper for simple JSON creation (for API responses) ---
// In a real-world scenario, use a robust JSON library like nlohmann/json.
std::string createSimpleJson(const std::unordered_map<std::string, std::string>& data) {
    std::stringstream ss;
    ss << "{";
    bool first = true;
    for (const auto& pair : data) {
        if (!first) {
            ss << ",";
        }
        // Basic escaping for values. Keys are assumed to be safe.
        std::string escaped_value = pair.second;
        // Replace " with \"
        size_t pos = escaped_value.find("\"");
        while(pos != std::string::npos) {
            escaped_value.replace(pos, 1, "\\\"");
            pos = escaped_value.find("\"", pos + 2);
        }
        ss << "\"" << pair.first << ":\"" << escaped_value << "\"";
        first = false;
    }
    ss << "}";
    return ss.str();
}

