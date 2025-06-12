package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
)

// MCPHandler handles MCP requests with per-user instance management
type MCPHandler struct {
	serverName   string
	serverConfig *config.MCPClientConfig
	userManager  *client.UserMCPManager
	oauthServer  *oauth.Server
	setupBaseURL string
	info         mcp.Implementation
}

// NewMCPHandler creates a new MCP handler
func NewMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	userManager *client.UserMCPManager,
	oauthServer *oauth.Server,
	setupBaseURL string,
	info mcp.Implementation,
) *MCPHandler {
	return &MCPHandler{
		serverName:   serverName,
		serverConfig: serverConfig,
		userManager:  userManager,
		oauthServer:  oauthServer,
		setupBaseURL: setupBaseURL,
		info:         info,
	}
}

// ServeHTTP handles incoming MCP requests
func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Determine if this server requires user tokens
	if h.serverConfig.RequiresUserToken {
		// Get user email from context (set by OAuth middleware)
		userEmail, ok := oauth.GetUserFromContext(ctx)
		if !ok {
			internal.LogErrorWithFields("mcp", "No user email in context", map[string]interface{}{
				"service": h.serverName,
			})
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Get user's token for this service
		tokenStore := h.oauthServer.GetUserTokenStore()
		userToken, err := tokenStore.GetUserToken(ctx, userEmail, h.serverName)
		if err != nil {
			if errors.Is(err, oauth.ErrUserTokenNotFound) {
				internal.LogInfoWithFields("mcp", "User has not configured token", map[string]interface{}{
					"user":    userEmail,
					"service": h.serverName,
				})
				sendTokenRequiredError(w, h.serverName, h.serverConfig, h.setupBaseURL)
				return
			}
			internal.LogErrorWithFields("mcp", "Failed to get user token", map[string]interface{}{
				"error":   err.Error(),
				"user":    userEmail,
				"service": h.serverName,
			})
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Validate token format if specified
		if h.serverConfig.TokenSetup != nil && h.serverConfig.TokenSetup.CompiledRegex != nil {
			if !h.serverConfig.TokenSetup.CompiledRegex.MatchString(userToken) {
				internal.LogWarnWithFields("mcp", "User token doesn't match expected format", map[string]interface{}{
					"user":    userEmail,
					"service": h.serverName,
				})
			}
		}

		// Get or create user-specific MCP instance
		var mcpClient *client.Client
		
		if isStdioServer(h.serverConfig) {
			// For stdio servers, create a new instance for each request
			mcpClient, err = h.userManager.CreateStdioInstance(ctx, userEmail, h.serverName, h.serverConfig, userToken)
		} else {
			// For SSE servers, reuse existing instance
			mcpClient, err = h.userManager.GetOrCreateInstance(ctx, userEmail, h.serverName, h.serverConfig, userToken)
		}

		if err != nil {
			internal.LogErrorWithFields("mcp", "Failed to get/create MCP instance", map[string]interface{}{
				"error":   err.Error(),
				"user":    userEmail,
				"service": h.serverName,
			})
			http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
			return
		}

		// Create server instance for this user
		server := client.NewMCPServer(h.serverName, "dev", h.setupBaseURL, h.serverConfig)
		
		// Add client to server if not already added
		if err := mcpClient.AddToMCPServer(ctx, h.info, server.MCPServer); err != nil {
			internal.LogErrorWithFields("mcp", "Failed to add client to server", map[string]interface{}{
				"error":   err.Error(),
				"user":    userEmail,
				"service": h.serverName,
			})
			http.Error(w, "Failed to initialize service", http.StatusInternalServerError)
			return
		}

		// Handle the SSE request
		server.SSEServer.ServeHTTP(w, r)
	} else {
		// For services that don't require user tokens, we still need to create
		// a shared instance (this maintains backward compatibility)
		sharedClient, err := h.getSharedInstance(ctx)
		if err != nil {
			internal.LogErrorWithFields("mcp", "Failed to get shared MCP instance", map[string]interface{}{
				"error":   err.Error(),
				"service": h.serverName,
			})
			http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
			return
		}

		// Create server instance
		server := client.NewMCPServer(h.serverName, "dev", h.setupBaseURL, h.serverConfig)
		
		// Add client to server if not already added
		if err := sharedClient.AddToMCPServer(ctx, h.info, server.MCPServer); err != nil {
			internal.LogErrorWithFields("mcp", "Failed to add client to server", map[string]interface{}{
				"error":   err.Error(),
				"service": h.serverName,
			})
			http.Error(w, "Failed to initialize service", http.StatusInternalServerError)
			return
		}

		// Handle the SSE request
		server.SSEServer.ServeHTTP(w, r)
	}
}

// getSharedInstance gets or creates a shared instance for non-user-specific servers
func (h *MCPHandler) getSharedInstance(ctx context.Context) (*client.Client, error) {
	// Use a special key for shared instances
	return h.userManager.GetOrCreateInstance(ctx, "__shared__", h.serverName, h.serverConfig, "")
}

// isStdioServer determines if this is a stdio-based server
func isStdioServer(cfg *config.MCPClientConfig) bool {
	return cfg.TransportType == config.MCPClientTypeStdio || cfg.Command != ""
}