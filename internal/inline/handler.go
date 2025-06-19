package inline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/server/sse"
)

// MCPServer defines the interface that Handler depends on
type MCPServer interface {
	GetCapabilities() ServerCapabilities
	HandleToolCall(ctx context.Context, toolName string, args map[string]interface{}) (interface{}, error)
	GetDescription() string
}

// Handler implements the MCP protocol for inline servers
type Handler struct {
	server MCPServer
	name   string
}

// NewHandler creates a new inline MCP handler
func NewHandler(name string, server MCPServer) *Handler {
	return &Handler{
		server: server,
		name:   name,
	}
}

// ServeHTTP handles HTTP requests for the inline MCP server
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/sse" || r.URL.Path == "/"+h.name+"/sse" {
		h.handleSSE(w, r)
	} else if r.URL.Path == "/message" || r.URL.Path == "/"+h.name+"/message" {
		h.handleMessage(w, r)
	} else {
		http.NotFound(w, r)
	}
}

// handleSSE handles SSE connections
func (h *Handler) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set up SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Generate a cryptographically secure session ID
	sessionID := crypto.GenerateSecureToken()

	// Send initial endpoint message
	endpoint := map[string]interface{}{
		"type":        "endpoint",
		"name":        h.name,
		"version":     "1.0",
		"description": h.server.GetDescription(),
	}

	if err := sse.WriteMessage(w, flusher, endpoint); err != nil {
		internal.LogError("Failed to write endpoint message: %v", err)
		return
	}

	// Send message endpoint path for MCP protocol
	// MCP clients expect to receive the message endpoint after the endpoint message
	// Send as relative path - client will construct full URL based on where it connected
	messageEndpointPath := fmt.Sprintf("/%s/message?sessionId=%s", h.name, sessionID)
	if err := sse.WriteMessage(w, flusher, messageEndpointPath); err != nil {
		internal.LogError("Failed to write message endpoint path: %v", err)
		return
	}

	// Start the SSE loop
	h.runSSELoop(r.Context(), w, flusher)
}

// runSSELoop runs the SSE keep-alive loop - extracted for testability
func (h *Handler) runSSELoop(ctx context.Context, w http.ResponseWriter, flusher http.Flusher) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send ping to keep connection alive
			if err := sse.WriteMessage(w, flusher, map[string]interface{}{
				"type": "ping",
			}); err != nil {
				return
			}
		}
	}
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// handleMessage handles JSON-RPC messages
func (h *Handler) handleMessage(w http.ResponseWriter, r *http.Request) {
	// For inline servers, we accept any sessionId parameter without validation
	// since inline servers are stateless and don't track sessions
	_ = r.URL.Query().Get("sessionId") // Accept but don't validate

	var request JSONRPCRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		// Invalid JSON should return HTTP 400
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error: map[string]interface{}{
				"code":    -32700,
				"message": "Invalid JSON",
			},
		}); err != nil {
			internal.LogError("Failed to encode JSON-RPC error response: %v", err)
		}
		return
	}

	switch request.Method {
	case "initialize":
		h.handleInitialize(w, &request)
	case "tools/list":
		h.handleToolsList(w, &request)
	case "tools/call":
		h.handleToolCall(w, &request)
	default:
		writeJSONRPCError(w, request.ID, -32601, "Method not found")
	}
}

// handleInitialize handles the initialize request
func (h *Handler) handleInitialize(w http.ResponseWriter, req *JSONRPCRequest) {
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    h.server.GetCapabilities(),
			"serverInfo": map[string]interface{}{
				"name":    h.name,
				"version": "1.0",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogError("Failed to encode JSON-RPC response: %v", err)
	}
}

// handleToolsList handles the tools/list request
func (h *Handler) handleToolsList(w http.ResponseWriter, req *JSONRPCRequest) {
	capabilities := h.server.GetCapabilities()

	tools := make([]map[string]interface{}, 0, len(capabilities.Tools))
	for _, tool := range capabilities.Tools {
		tools = append(tools, map[string]interface{}{
			"name":        tool.Name,
			"description": tool.Description,
			"inputSchema": tool.InputSchema,
		})
	}

	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogError("Failed to encode JSON-RPC response: %v", err)
	}
}

// handleToolCall handles tool execution requests
func (h *Handler) handleToolCall(w http.ResponseWriter, req *JSONRPCRequest) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPCError(w, req.ID, -32602, "Invalid parameters")
		return
	}

	// Execute the tool
	result, err := h.server.HandleToolCall(context.Background(), params.Name, params.Arguments)
	if err != nil {
		writeJSONRPCError(w, req.ID, -32603, err.Error())
		return
	}

	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": formatToolResult(result),
				},
			},
			"isError": err != nil,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogError("Failed to encode JSON-RPC response: %v", err)
	}
}

// formatToolResult formats the tool result for display
func formatToolResult(result interface{}) string {
	// If it's already a string, return it
	if str, ok := result.(string); ok {
		return str
	}

	// If it's a map with output field, return that
	if m, ok := result.(map[string]interface{}); ok {
		if output, exists := m["output"]; exists {
			if str, ok := output.(string); ok {
				return str
			}
		}
	}

	// Otherwise, marshal as JSON
	bytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", result)
	}
	return string(bytes)
}

// writeJSONRPCError writes a JSON-RPC error response
func writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogError("Failed to encode JSON-RPC response: %v", err)
	}
}
