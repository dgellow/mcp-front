package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// MCPHandler handles MCP requests with session management for stdio servers
type MCPHandler struct {
	serverName      string
	serverConfig    *config.MCPClientConfig
	tokenStore      storage.UserTokenStore
	setupBaseURL    string
	info            mcp.Implementation
	sessionManager  *client.StdioSessionManager
	sharedSSEServer *server.SSEServer // Shared SSE server for stdio servers
}

// NewMCPHandler creates a new MCP handler with session management
func NewMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	tokenStore storage.UserTokenStore,
	setupBaseURL string,
	info mcp.Implementation,
	sessionManager *client.StdioSessionManager,
	sharedSSEServer *server.SSEServer, // Shared SSE server for stdio servers
) *MCPHandler {
	return &MCPHandler{
		serverName:      serverName,
		serverConfig:    serverConfig,
		tokenStore:      tokenStore,
		setupBaseURL:    setupBaseURL,
		info:            info,
		sessionManager:  sessionManager,
		sharedSSEServer: sharedSSEServer,
	}
}

func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context if OAuth middleware set it
	userEmail, _ := oauth.GetUserFromContext(ctx)

	// Get user token if available for applying to config
	// Don't block connection if missing - will check at tool invocation
	var userToken string
	if h.serverConfig.RequiresUserToken && userEmail != "" {
		userToken, _ = h.getUserTokenIfAvailable(ctx, userEmail)
	}

	// Apply user token to config if available
	config := h.serverConfig
	if userToken != "" {
		config = config.ApplyUserToken(userToken)
	}

	// Determine request type and route accordingly
	if h.isMessageRequest(r) {
		internal.LogInfoWithFields("mcp", "Handling message request", map[string]interface{}{
			"path":          r.URL.Path,
			"server":        h.serverName,
			"isStdio":       isStdioServer(config),
			"user":          userEmail,
			"remoteAddr":    r.RemoteAddr,
			"contentLength": r.ContentLength,
			"query":         r.URL.RawQuery,
		})
		h.handleMessageRequest(ctx, w, r, userEmail, config)
	} else {
		// Handle as SSE request (including legacy paths)
		internal.LogInfoWithFields("mcp", "Handling SSE request", map[string]interface{}{
			"path":       r.URL.Path,
			"server":     h.serverName,
			"isStdio":    isStdioServer(config),
			"user":       userEmail,
			"remoteAddr": r.RemoteAddr,
			"userAgent":  r.UserAgent(),
		})
		h.handleSSERequest(ctx, w, r, userEmail, config)
	}
}

// isMessageRequest checks if this is a message endpoint request
func (h *MCPHandler) isMessageRequest(r *http.Request) bool {
	// Check if path ends with /message or contains /message?
	path := r.URL.Path
	return strings.HasSuffix(path, "/message") || strings.Contains(path, "/message?")
}

// handleSSERequest handles SSE connection requests for stdio servers
func (h *MCPHandler) handleSSERequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	// Track user access
	if userEmail != "" {
		if store, ok := h.tokenStore.(storage.Storage); ok {
			if err := store.UpsertUser(ctx, userEmail); err != nil {
				internal.LogWarnWithFields("mcp", "Failed to track user", map[string]interface{}{
					"error": err.Error(),
					"user":  userEmail,
				})
			}
		}
	}

	if !isStdioServer(config) {
		// For non-stdio servers, handle normally
		h.handleNonStdioSSERequest(ctx, w, r, userEmail, config)
		return
	}

	// For stdio servers, use the shared SSE server
	if h.sharedSSEServer == nil {
		internal.LogErrorWithFields("mcp", "No shared SSE server configured for stdio server", map[string]interface{}{
			"server": h.serverName,
		})
		http.Error(w, "Server misconfiguration", http.StatusInternalServerError)
		return
	}

	// The shared MCP server already has hooks configured in handler.go
	// that will be called when sessions are registered/unregistered
	// We need to set up our session-specific handlers
	// Create a custom hook handler for this specific request
	sessionHandler := &sessionRequestHandler{
		h:         h,
		userEmail: userEmail,
		config:    config,
	}

	// Store the handler in context so hooks can access it
	ctx = context.WithValue(ctx, sessionHandlerKey{}, sessionHandler)
	r = r.WithContext(ctx)
	internal.LogInfoWithFields("mcp", "Serving SSE request for stdio server", map[string]interface{}{
		"server": h.serverName,
		"user":   userEmail,
		"path":   r.URL.Path,
	})

	// Use the shared SSE server directly
	h.sharedSSEServer.ServeHTTP(w, r)
}

// handleMessageRequest handles message endpoint requests for stdio servers
func (h *MCPHandler) handleMessageRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	// Track user access
	if userEmail != "" {
		if store, ok := h.tokenStore.(storage.Storage); ok {
			if err := store.UpsertUser(ctx, userEmail); err != nil {
				internal.LogWarnWithFields("mcp", "Failed to track user", map[string]interface{}{
					"error": err.Error(),
					"user":  userEmail,
				})
			}
		}
	}

	if !isStdioServer(config) {
		h.writeJSONRPCError(w, nil, mcp.INVALID_REQUEST, "Message endpoint not supported for this transport")
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		h.writeJSONRPCError(w, nil, mcp.INVALID_PARAMS, "Missing sessionId")
		return
	}

	// Look up existing stdio session
	key := client.SessionKey{
		UserEmail:  userEmail,
		ServerName: h.serverName,
		SessionID:  sessionID,
	}

	internal.LogDebugWithFields("mcp", "Looking up session", map[string]interface{}{
		"sessionID": sessionID,
		"server":    h.serverName,
		"user":      userEmail,
	})

	internal.LogDebugWithFields("mcp", "About to call GetSession", map[string]interface{}{
		"key": key,
	})

	_, ok := h.sessionManager.GetSession(key)

	internal.LogDebugWithFields("mcp", "GetSession returned", map[string]interface{}{
		"found": ok,
		"key":   key,
	})

	if !ok {
		internal.LogWarnWithFields("mcp", "Session not found - returning 404 with JSON-RPC error per MCP spec", map[string]interface{}{
			"sessionID": sessionID,
			"server":    h.serverName,
			"user":      userEmail,
		})
		// Per MCP spec: return HTTP 404 Not Found when session is terminated or not found
		// The response body MAY comprise a JSON-RPC error response
		h.writeJSONRPCErrorWithStatus(w, nil, mcp.INVALID_PARAMS, "Session not found", http.StatusNotFound)
		return
	}

	// For stdio servers, use the shared SSE server
	if h.sharedSSEServer == nil {
		internal.LogErrorWithFields("mcp", "No shared SSE server configured", map[string]interface{}{
			"sessionID": sessionID,
		})
		h.writeJSONRPCError(w, nil, mcp.INTERNAL_ERROR, "Server misconfiguration")
		return
	}

	internal.LogDebugWithFields("mcp", "Forwarding message request to shared SSE server", map[string]interface{}{
		"sessionID": sessionID,
		"server":    h.serverName,
		"user":      userEmail,
	})

	// Use the shared SSE server directly
	h.sharedSSEServer.ServeHTTP(w, r)
}

// handleNonStdioSSERequest handles SSE requests for non-stdio (native SSE) servers
func (h *MCPHandler) handleNonStdioSSERequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	// Create MCP client
	mcpClient, err := client.NewMCPClient(h.serverName, config)
	if err != nil {
		internal.LogErrorWithFields("mcp", "Failed to create MCP client", map[string]interface{}{
			"error":   err.Error(),
			"user":    userEmail,
			"service": h.serverName,
		})
		http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
		return
	}
	defer mcpClient.Close()

	// Create MCP server
	mcpServer := server.NewMCPServer(h.serverName, "1.0.0",
		server.WithPromptCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithToolCapabilities(true),
		server.WithLogging(),
	)

	// Connect client to server
	if err := mcpClient.AddToMCPServerWithTokenCheck(
		ctx,
		h.info,
		mcpServer,
		userEmail,
		h.serverConfig.RequiresUserToken,
		h.tokenStore,
		h.serverName,
		h.setupBaseURL,
		h.serverConfig.TokenSetup,
	); err != nil {
		internal.LogErrorWithFields("mcp", "Failed to connect client to server", map[string]interface{}{
			"error":   err.Error(),
			"user":    userEmail,
			"service": h.serverName,
		})
		http.Error(w, "Failed to initialize service", http.StatusInternalServerError)
		return
	}

	// Create SSE server and serve
	sseServer := server.NewSSEServer(mcpServer,
		server.WithStaticBasePath(h.serverName),
		server.WithBaseURL(h.setupBaseURL),
	)

	internal.LogInfoWithFields("mcp", "Serving SSE request", map[string]interface{}{
		"service": h.serverName,
		"isStdio": false,
		"user":    userEmail,
	})

	sseServer.ServeHTTP(w, r)
}

// getUserTokenIfAvailable gets the user token if available, but doesn't send error responses
func (h *MCPHandler) getUserTokenIfAvailable(ctx context.Context, userEmail string) (string, error) {
	if userEmail == "" {
		return "", fmt.Errorf("authentication required")
	}

	token, err := h.tokenStore.GetUserToken(ctx, userEmail, h.serverName)
	if err != nil {
		return "", err
	}

	// Validate token format if configured
	if h.serverConfig.TokenSetup != nil && h.serverConfig.TokenSetup.CompiledRegex != nil {
		if !h.serverConfig.TokenSetup.CompiledRegex.MatchString(token) {
			internal.LogWarnWithFields("mcp", "User token doesn't match expected format", map[string]interface{}{
				"user":    userEmail,
				"service": h.serverName,
			})
		}
	}

	return token, nil
}

// writeJSONRPCError writes a JSON-RPC error response with BadRequest status
func (h *MCPHandler) writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	h.writeJSONRPCErrorWithStatus(w, id, code, message, http.StatusBadRequest)
}

// writeJSONRPCErrorWithStatus writes a JSON-RPC error response with custom HTTP status
func (h *MCPHandler) writeJSONRPCErrorWithStatus(w http.ResponseWriter, id interface{}, code int, message string, httpStatus int) {
	// Map JSON-RPC 2.0 standard error codes to human-readable names
	// These are defined in the JSON-RPC 2.0 specification: https://www.jsonrpc.org/specification
	// Error codes from -32768 to -32000 are reserved for pre-defined errors
	var codeName string
	switch code {
	case -32700:
		codeName = "PARSE_ERROR" // Invalid JSON was received by the server
	case -32600:
		codeName = "INVALID_REQUEST" // The JSON sent is not a valid Request object
	case -32601:
		codeName = "METHOD_NOT_FOUND" // The method does not exist / is not available
	case -32602:
		codeName = "INVALID_PARAMS" // Invalid method parameter(s)
	case -32603:
		codeName = "INTERNAL_ERROR" // Internal JSON-RPC error
	default:
		if code >= -32099 && code <= -32000 {
			// -32000 to -32099: Reserved for implementation-defined server errors
			codeName = fmt.Sprintf("SERVER_ERROR_%d", -code-32000)
		} else {
			// Application-defined errors
			codeName = fmt.Sprintf("ERROR_%d", code)
		}
	}

	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
			"data": map[string]interface{}{
				"codeName": codeName,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogErrorWithFields("mcp", "Failed to encode error response", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
