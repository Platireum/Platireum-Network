Text file: api_server.h
Latest content with line numbers:
1	#ifndef API_SERVER_H
2	#define API_SERVER_H
3	
4	#include <string>
5	#include <memory>         // For std::shared_ptr
6	#include <functional>     // For std::function (callbacks)
7	#include <unordered_map>  // For managing API endpoints
8	#include <stdexcept>      // For custom exceptions
9	
10	// Forward declare Node or an interface for Node interaction
11	// The API server will need to call methods on the Node.
12	class Node;
13	
14	// --- 0. Error Handling ---
15	/**
16	 * @brief Custom exception class for API Server-specific errors.
17	 */
18	class ApiServerError : public std::runtime_error {
19	public:
20	    explicit ApiServerError(const std::string& msg) : std::runtime_error(msg) {}
21	};
22	
23	// --- 1. API Request/Response Structures (Simplified) ---
24	/**
25	 * @brief Represents a simplified API request.
26	 * In a real HTTP server, this would contain method (GET/POST), URL path, headers, and body.
27	 */
28	struct ApiRequest {
29	    std::string endpoint; // e.g., "/transactions", "/blocks/{hash}", "/mine"
30	    std::string method;   // e.g., "GET", "POST"
31	    std::string body;     // Request payload, typically JSON
32	    std::unordered_map<std::string, std::string> params; // URL or query parameters
33	
34	    // Constructor to easily create requests for testing
35	    ApiRequest(std::string ep, std::string m = "GET", std::string b = "",
36	               std::unordered_map<std::string, std::string> p = {})
37	        : endpoint(std::move(ep)), method(std::move(m)), body(std::move(b)), params(std::move(p)) {}
38	};
39	
40	/**
41	 * @brief Represents a simplified API response.
42	 * In a real HTTP server, this would contain status code, headers, and body.
43	 */
44	struct ApiResponse {
45	    int statusCode;
46	    std::string body;     // Response payload, typically JSON or plain text
47	    std::string errorMessage;    // Error message if any
48	
49	
50	
51	    ApiResponse(int code = 200, std::string b = "", std::string err = "")
52	        : statusCode(code), body(std::move(b)), errorMessage(std::move(err)) {}
53	
54	    // Helper to create common responses
55	    static ApiResponse success(const std::string& data) {
56	        return ApiResponse(200, data, "");
57	    }
58	    static ApiResponse error(int code, const std::string& msg) {
59	        return ApiResponse(code, "", msg);
60	    }
61	};
62	
63	// --- 2. API Server Class ---
64	/**
65	 * @brief A simplified API Server for blockchain interaction.
66	 *
67	 * This class simulates a server that receives API requests and processes them
68	 * by interacting with the blockchain Node. It uses callback functions to delegate
69	 * actual blockchain operations to the Node.
70	 *
71	 * In a production environment, this would be built using a robust web server library
72	 * (e.g., Boost.Beast, Crow, RESTinio) to handle actual network sockets, HTTP parsing,
73	 * and concurrent requests.
74	 */
75	class ApiServer {
76	private:
77	    std::string address; // IP address or hostname to bind to
78	    int port;            // Port number to listen on
79	    std::shared_ptr<Node> nodeInstance; // Reference to the blockchain node to interact with
80	
81	    // Define API handlers for different endpoints
82	    // Each handler takes an ApiRequest and returns an ApiResponse.
83	    using ApiHandler = std::function<ApiResponse(const ApiRequest&)>;
84	    std::unordered_map<std::string, ApiHandler> getHandlers;
85	    std::unordered_map<std::string, ApiHandler> postHandlers;
86	
87	    void log(const std::string& message) const;
88	
89	    // Private helper methods for handling specific requests
90	    ApiResponse handleGetNodeInfo(const ApiRequest& req);
91	    ApiResponse handlePostTransaction(const ApiRequest& req);
92	    ApiResponse handleGetBlock(const ApiRequest& req);
93	    ApiResponse handleMineBlock(const ApiRequest& req); // For demonstration/testing
94	    ApiResponse handleGetBlockchainState(const ApiRequest& req);
95	    ApiResponse handlePostDeployContract(const ApiRequest& req);
96	    ApiResponse handlePostCallContract(const ApiRequest& req);
97	
98	
99	public:
100	    /**
101	     * @brief Constructor for ApiServer.
102	     * @param addr The IP address or hostname for the server.
103	     * @param p The port number for the server.
104	     * @param node The shared_ptr to the blockchain Node instance this server will interact with.
105	     */
106	    ApiServer(const std::string& addr, int p, std::shared_ptr<Node> node);
107	
108	    /**
109	     * @brief Initializes the API server by registering its endpoints.
110	     * This method would typically be called once after construction.
111	     */
112	    void initialize();
113	
114	    /**
115	     * @brief Simulates starting the API server.
116	     * In a real implementation, this would involve binding to a socket and listening for connections.
117	     * For this simulation, it just logs a message.
118	     */
119	    void start();
120	
121	    /**
122	     * @brief Simulates processing an incoming API request.
123	     * In a real implementation, this would be called by the underlying HTTP server framework
124	     * when a client request arrives.
125	     * @param request The ApiRequest object representing the incoming client request.
126	     * @return An ApiResponse object containing the status and body of the response.
127	     */
128	    ApiResponse processRequest(const ApiRequest& request);
129	
130	    /**
131	     * @brief Stops the API server.
132	     */
133	    void stop();
134	};
135	
136	#endif // API_SERVER_H