#ifndef API_SERVER_H
#define API_SERVER_H

#include <string>
#include <memory>         // For std::shared_ptr
#include <functional>     // For std::function (callbacks)
#include <unordered_map>  // For managing API endpoints
#include <stdexcept>      // For custom exceptions

// Forward declare Node or an interface for Node interaction
// The API server will need to call methods on the Node.
class Node;

// --- 0. Error Handling ---
/**
 * @brief Custom exception class for API Server-specific errors.
 */
class ApiServerError : public std::runtime_error {
public:
    explicit ApiServerError(const std::string& msg) : std::runtime_error(msg) {}
};

// --- 1. API Request/Response Structures (Simplified) ---
/**
 * @brief Represents a simplified API request.
 * In a real HTTP server, this would contain method (GET/POST), URL path, headers, and body.
 */
struct ApiRequest {
    std::string endpoint; // e.g., "/transactions", "/blocks/{hash}", "/mine"
    std::string method;   // e.g., "GET", "POST"
    std::string body;     // Request payload, typically JSON
    std::unordered_map<std::string, std::string> params; // URL or query parameters

    // Constructor to easily create requests for testing
    ApiRequest(std::string ep, std::string m = "GET", std::string b = "",
               std::unordered_map<std::string, std::string> p = {})
        : endpoint(std::move(ep)), method(std::move(m)), body(std::move(b)), params(std::move(p)) {}
};

/**
 * @brief Represents a simplified API response.
 * In a real HTTP server, this would contain status code, headers, and body.
 */
struct ApiResponse {
    int statusCode;
    std::string body;     // Response payload, typically JSON or plain text
    std::string error;    // Error message if any

    ApiResponse(int code = 200, std::string b = "", std::string err = "")
        : statusCode(code), body(std::move(b)), error(std::move(err)) {}

    // Helper to create common responses
    static ApiResponse success(const std::string& data) {
        return ApiResponse(200, data, "");
    }
    static ApiResponse error(int code, const std::string& msg) {
        return ApiResponse(code, "", msg);
    }
};

// --- 2. API Server Class ---
/**
 * @brief A simplified API Server for blockchain interaction.
 *
 * This class simulates a server that receives API requests and processes them
 * by interacting with the blockchain Node. It uses callback functions to delegate
 * actual blockchain operations to the Node.
 *
 * In a production environment, this would be built using a robust web server library
 * (e.g., Boost.Beast, Crow, RESTinio) to handle actual network sockets, HTTP parsing,
 * and concurrent requests.
 */
class ApiServer {
private:
    std::string address; // IP address or hostname to bind to
    int port;            // Port number to listen on
    std::shared_ptr<Node> nodeInstance; // Reference to the blockchain node to interact with

    // Define API handlers for different endpoints
    // Each handler takes an ApiRequest and returns an ApiResponse.
    using ApiHandler = std::function<ApiResponse(const ApiRequest&)>;
    std::unordered_map<std::string, ApiHandler> getHandlers;
    std::unordered_map<std::string, ApiHandler> postHandlers;

    void log(const std::string& message) const;

    // Private helper methods for handling specific requests
    ApiResponse handleGetNodeInfo(const ApiRequest& req);
    ApiResponse handlePostTransaction(const ApiRequest& req);
    ApiResponse handleGetBlock(const ApiRequest& req);
    ApiResponse handleMineBlock(const ApiRequest& req); // For demonstration/testing
    ApiResponse handleGetBlockchainState(const ApiRequest& req);
    ApiResponse handlePostDeployContract(const ApiRequest& req);
    ApiResponse handlePostCallContract(const ApiRequest& req);


public:
    /**
     * @brief Constructor for ApiServer.
     * @param addr The IP address or hostname for the server.
     * @param p The port number for the server.
     * @param node The shared_ptr to the blockchain Node instance this server will interact with.
     */
    ApiServer(const std::string& addr, int p, std::shared_ptr<Node> node);

    /**
     * @brief Initializes the API server by registering its endpoints.
     * This method would typically be called once after construction.
     */
    void initialize();

    /**
     * @brief Simulates starting the API server.
     * In a real implementation, this would involve binding to a socket and listening for connections.
     * For this simulation, it just logs a message.
     */
    void start();

    /**
     * @brief Simulates processing an incoming API request.
     * In a real implementation, this would be called by the underlying HTTP server framework
     * when a client request arrives.
     * @param request The ApiRequest object representing the incoming client request.
     * @return An ApiResponse object containing the status and body of the response.
     */
    ApiResponse processRequest(const ApiRequest& request);

    /**
     * @brief Stops the API server.
     */
    void stop();
};

#endif // API_SERVER_H