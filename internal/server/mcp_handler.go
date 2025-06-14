package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// MCPHandler handles MCP requests with session management for stdio servers
type MCPHandler struct {
	serverName      string
	serverConfig    *config.MCPClientConfig
	tokenStore      oauth.UserTokenStore
	setupBaseURL    string
	info            mcp.Implementation
	sessionManager  *client.StdioSessionManager
	sharedSSEServer *server.SSEServer // Shared SSE server for stdio servers
	capabilitiesLoaded bool // Track if capabilities have been loaded
	capabilitiesMu     sync.RWMutex // Protect capabilities loading
}

// NewMCPHandler creates a new MCP handler with session management
func NewMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	tokenStore oauth.UserTokenStore,
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

	// Check if user token is required and get it
	userToken, err := h.getUserTokenIfRequired(ctx, w, userEmail)
	if err != nil {
		return // Error already handled
	}

	// Apply user token to config if needed
	config := h.serverConfig
	if userToken != "" && config.RequiresUserToken {
		config = config.ApplyUserToken(userToken)
	}

	// Determine request type and route accordingly
	if h.isMessageRequest(r) {
		internal.LogInfoWithFields("mcp", "Handling message request", map[string]interface{}{
			"path":   r.URL.Path,
			"server": h.serverName,
			"isStdio": isStdioServer(config),
		})
		h.handleMessageRequest(ctx, w, r, userEmail, config)
	} else {
		// Handle as SSE request (including legacy paths)
		internal.LogInfoWithFields("mcp", "Handling SSE request", map[string]interface{}{
			"path":   r.URL.Path,
			"server": h.serverName,
			"isStdio": isStdioServer(config),
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
		internal.LogWarnWithFields("mcp", "Session not found", map[string]interface{}{
			"sessionID": sessionID,
			"server":    h.serverName,
			"user":      userEmail,
		})
		h.writeJSONRPCError(w, nil, mcp.INVALID_PARAMS, "Invalid session ID")
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
	if err := mcpClient.AddToMCPServer(ctx, h.info, mcpServer); err != nil {
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

// getUserTokenIfRequired gets the user token if the server requires it
func (h *MCPHandler) getUserTokenIfRequired(ctx context.Context, w http.ResponseWriter, userEmail string) (string, error) {
	if !h.serverConfig.RequiresUserToken {
		return "", nil
	}

	if userEmail == "" {
		internal.LogErrorWithFields("mcp", "Server requires user token but no authenticated user", map[string]interface{}{
			"service": h.serverName,
		})
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return "", fmt.Errorf("authentication required")
	}

	token, err := h.tokenStore.GetUserToken(ctx, userEmail, h.serverName)
	if err != nil {
		if errors.Is(err, oauth.ErrUserTokenNotFound) {
			h.sendTokenSetupInstructions(w, userEmail)
			return "", fmt.Errorf("token setup required")
		}
		internal.LogErrorWithFields("mcp", "Failed to get user token", map[string]interface{}{
			"error":   err.Error(),
			"user":    userEmail,
			"service": h.serverName,
		})
		http.Error(w, "Internal error", http.StatusInternalServerError)
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

// sendTokenSetupInstructions sends SSE event with token setup instructions
func (h *MCPHandler) sendTokenSetupInstructions(w http.ResponseWriter, userEmail string) {
	internal.LogInfoWithFields("mcp", "Sending token setup instructions", map[string]interface{}{
		"user":    userEmail,
		"service": h.serverName,
	})

	// Send SSE error event that Claude can understand
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK) // SSE requires 200 OK

	// Create error message with instructions
	tokenSetupURL := fmt.Sprintf("%s/my/tokens", h.setupBaseURL)

	var errorMessage string
	if h.serverConfig.TokenSetup != nil {
		errorMessage = fmt.Sprintf(
			"Token Required: %s requires a user token to access the API. "+
				"Please visit %s to set up your %s token. %s",
			h.serverConfig.TokenSetup.DisplayName,
			tokenSetupURL,
			h.serverConfig.TokenSetup.DisplayName,
			h.serverConfig.TokenSetup.Instructions,
		)
	} else {
		errorMessage = fmt.Sprintf(
			"Token Required: This service requires a user token. "+
				"Please visit %s to configure your token.",
			tokenSetupURL,
		)
	}

	// Send SSE error event
	errorEvent := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    "token_required",
			"message": errorMessage,
			"data": map[string]interface{}{
				"service":       h.serverName,
				"tokenSetupUrl": tokenSetupURL,
				"instructions": map[string]interface{}{
					"ai": "CRITICAL: You MUST pass these error details EXACTLY as provided to the human. " +
						"You are FORBIDDEN from modifying URLs or instructions. " +
						"Tell the human they need to visit the tokenSetupUrl to configure their token.",
					"human": errorMessage,
				},
			},
		},
	}

	// Marshal and send as SSE event
	data, _ := json.Marshal(errorEvent)
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}


// writeJSONRPCError writes a JSON-RPC error response
func (h *MCPHandler) writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogErrorWithFields("mcp", "Failed to encode error response", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
