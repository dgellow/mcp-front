package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type MCPHandler struct {
	serverName     string
	serverConfig   *config.MCPClientConfig
	tokenStore     oauth.UserTokenStore
	setupBaseURL   string
	info           mcp.Implementation
	// Accept interface for testing, return concrete types
	clientFactory  ClientFactory
}

// ClientFactory creates MCP clients - accept interface for testability
type ClientFactory interface {
	CreateClient(ctx context.Context, name string, config *config.MCPClientConfig) (*client.Client, error)
}

// MCPClient is what we need from a client - accept interface
type MCPClient interface {
	AddToMCPServer(ctx context.Context, info mcp.Implementation, srv *server.MCPServer) error
	Close() error
}

func NewMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	tokenStore oauth.UserTokenStore,
	setupBaseURL string,
	info mcp.Implementation,
) *MCPHandler {
	return &MCPHandler{
		serverName:    serverName,
		serverConfig:  serverConfig,
		tokenStore:    tokenStore,
		setupBaseURL:  setupBaseURL,
		info:          info,
		clientFactory: &defaultClientFactory{},
	}
}

// NewMCPHandlerWith allows dependency injection for testing
func NewMCPHandlerWith(
	serverName string,
	serverConfig *config.MCPClientConfig,
	tokenStore oauth.UserTokenStore,
	setupBaseURL string,
	info mcp.Implementation,
	clientFactory ClientFactory,
) *MCPHandler {
	return &MCPHandler{
		serverName:    serverName,
		serverConfig:  serverConfig,
		tokenStore:    tokenStore,
		setupBaseURL:  setupBaseURL,
		info:          info,
		clientFactory: clientFactory,
	}
}

func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context (set by OAuth middleware if auth is configured)
	userEmail, ok := oauth.GetUserFromContext(ctx)
	if !ok {
		// If no user context and we have a token store, auth is required
		if h.tokenStore != nil {
			internal.LogErrorWithFields("mcp", "No user email in context", map[string]interface{}{
				"service": h.serverName,
			})
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		// No auth configured, use empty user email
		userEmail = ""
	}

	// Get user token if required
	userToken := ""
	if h.serverConfig.RequiresUserToken {
		token, err := h.tokenStore.GetUserToken(ctx, userEmail, h.serverName)
		if err != nil {
			if errors.Is(err, oauth.ErrUserTokenNotFound) {
				// Send token setup instructions
				h.sendTokenSetupInstructions(w, userEmail)
				return
			}
			internal.LogErrorWithFields("mcp", "Failed to get user token", map[string]interface{}{
				"error":   err.Error(),
				"user":    userEmail,
				"service": h.serverName,
			})
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		userToken = token

		// Validate token format if configured
		if h.serverConfig.TokenSetup != nil && h.serverConfig.TokenSetup.CompiledRegex != nil {
			if !h.serverConfig.TokenSetup.CompiledRegex.MatchString(userToken) {
				internal.LogWarnWithFields("mcp", "User token doesn't match expected format", map[string]interface{}{
					"user":    userEmail,
					"service": h.serverName,
				})
			}
		}
	}

	// Handle the request
	h.handleMCPRequest(ctx, w, r, userEmail, userToken)
}

func (h *MCPHandler) handleMCPRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail, userToken string) {
	// Apply user token if needed
	config := h.serverConfig
	if userToken != "" && config.RequiresUserToken {
		config = config.ApplyUserToken(userToken)
	}

	// Create MCP client - returns concrete type
	mcpClient, err := h.clientFactory.CreateClient(ctx, h.serverName, config)
	if err != nil {
		internal.LogErrorWithFields("mcp", "Failed to create MCP client", map[string]interface{}{
			"error":   err.Error(),
			"user":    userEmail,
			"service": h.serverName,
		})
		http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
		return
	}
	
	// For stdio servers, defer close. For SSE servers, we handle it manually.
	isStdio := isStdioServer(config)
	if isStdio {
		defer func() {
			if err := mcpClient.Close(); err != nil {
				internal.LogErrorWithFields("mcp", "Failed to close MCP client", map[string]interface{}{
					"error":   err.Error(),
					"user":    userEmail,
					"service": h.serverName,
				})
			}
		}()
	}

	// Create MCP server - return concrete type, no unsafe assertions needed
	mcpServerWrapper := client.NewMCPServer(h.serverName, "dev", h.setupBaseURL, config)
	
	// Connect client to server - no type assertion needed
	if err := mcpClient.AddToMCPServer(ctx, h.info, mcpServerWrapper.MCPServer); err != nil {
		// For SSE servers, we need to close on error since we didn't defer it
		if !isStdio {
			if closeErr := mcpClient.Close(); closeErr != nil {
				internal.LogErrorWithFields("mcp", "Failed to close MCP client after connection error", map[string]interface{}{
					"error":   closeErr.Error(),
					"user":    userEmail,
					"service": h.serverName,
				})
			}
		}
		internal.LogErrorWithFields("mcp", "Failed to connect client to server", map[string]interface{}{
			"error":   err.Error(),
			"user":    userEmail,
			"service": h.serverName,
		})
		http.Error(w, "Failed to initialize service", http.StatusInternalServerError)
		return
	}

	// Handle the SSE request
	// Note: For SSE servers, the connection remains open for the duration of the SSE stream
	if !isStdio {
		// For SSE connections, ensure cleanup when done
		defer func() {
			if err := mcpClient.Close(); err != nil {
				internal.LogErrorWithFields("mcp", "Failed to close MCP client", map[string]interface{}{
					"error":   err.Error(),
					"user":    userEmail,
					"service": h.serverName,
				})
			}
		}()
	}
	mcpServerWrapper.SSEServer.ServeHTTP(w, r)
}

// defaultClientFactory is the production implementation
type defaultClientFactory struct{}

func (f *defaultClientFactory) CreateClient(ctx context.Context, name string, config *config.MCPClientConfig) (*client.Client, error) {
	return client.NewMCPClient(name, config)
}

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

// isStdioServer checks if this is a stdio-based server
func isStdioServer(config *config.MCPClientConfig) bool {
	return config.Command != ""
}

