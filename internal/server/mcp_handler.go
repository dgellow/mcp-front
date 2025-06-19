package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
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
		internal.LogInfoWithFields("mcp", "Handling message request", map[string]any{
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
		internal.LogInfoWithFields("mcp", "Handling SSE request", map[string]any{
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
				internal.LogWarnWithFields("mcp", "Failed to track user", map[string]any{
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
		internal.LogErrorWithFields("mcp", "No shared SSE server configured for stdio server", map[string]any{
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
	internal.LogInfoWithFields("mcp", "Serving SSE request for stdio server", map[string]any{
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
				internal.LogWarnWithFields("mcp", "Failed to track user", map[string]any{
					"error": err.Error(),
					"user":  userEmail,
				})
			}
		}
	}

	if !isStdioServer(config) {
		jsonrpc.WriteError(w, nil, jsonrpc.InvalidRequest, "Message endpoint not supported for this transport")
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		jsonrpc.WriteError(w, nil, jsonrpc.InvalidParams, "Missing sessionId")
		return
	}

	// Look up existing stdio session
	key := client.SessionKey{
		UserEmail:  userEmail,
		ServerName: h.serverName,
		SessionID:  sessionID,
	}

	internal.LogDebugWithFields("mcp", "Looking up session", map[string]any{
		"sessionID": sessionID,
		"server":    h.serverName,
		"user":      userEmail,
	})

	internal.LogDebugWithFields("mcp", "About to call GetSession", map[string]any{
		"key": key,
	})

	_, ok := h.sessionManager.GetSession(key)

	internal.LogDebugWithFields("mcp", "GetSession returned", map[string]any{
		"found": ok,
		"key":   key,
	})

	if !ok {
		internal.LogWarnWithFields("mcp", "Session not found - returning 404 with JSON-RPC error per MCP spec", map[string]any{
			"sessionID": sessionID,
			"server":    h.serverName,
			"user":      userEmail,
		})
		// Per MCP spec: return HTTP 404 Not Found when session is terminated or not found
		// The response body MAY comprise a JSON-RPC error response
		jsonrpc.WriteErrorWithStatus(w, nil, jsonrpc.InvalidParams, "Session not found", http.StatusNotFound)
		return
	}

	// For stdio servers, use the shared SSE server
	if h.sharedSSEServer == nil {
		internal.LogErrorWithFields("mcp", "No shared SSE server configured", map[string]any{
			"sessionID": sessionID,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "Server misconfiguration")
		return
	}

	internal.LogDebugWithFields("mcp", "Forwarding message request to shared SSE server", map[string]any{
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
		internal.LogErrorWithFields("mcp", "Failed to create MCP client", map[string]any{
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
		internal.LogErrorWithFields("mcp", "Failed to connect client to server", map[string]any{
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

	internal.LogInfoWithFields("mcp", "Serving SSE request", map[string]any{
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
			internal.LogWarnWithFields("mcp", "User token doesn't match expected format", map[string]any{
				"user":    userEmail,
				"service": h.serverName,
			})
		}
	}

	return token, nil
}
