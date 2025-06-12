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
	"github.com/mark3labs/mcp-go/server"
)

// UserTokenGetter provides access to user tokens
type UserTokenGetter interface {
	GetUserToken(ctx context.Context, userEmail, serviceName string) (string, error)
}

// MCPClient represents an MCP client that can be added to servers and closed
type MCPClient interface {
	AddToMCPServer(ctx context.Context, info mcp.Implementation, mcpServer *server.MCPServer) error
	Close() error
}

// UserMCPManager provides user-scoped MCP instances
type UserMCPManager interface {
	CreateStdioInstance(ctx context.Context, user, serverName string, config *config.MCPClientConfig, userToken string) (*client.Client, error)
	GetOrCreateSSEServer(ctx context.Context, user, serverName string, config *config.MCPClientConfig, userToken string, info mcp.Implementation, setupBaseURL string) (*client.Server, error)
}

// MCPHandler handles MCP requests with per-user instance management
type MCPHandler struct {
	serverName        string
	serverConfig      *config.MCPClientConfig
	userManager       UserMCPManager
	userTokenStore    UserTokenGetter
	setupBaseURL      string
	info              mcp.Implementation
	newMCPServerFunc  func(name, version, baseURL string, config *config.MCPClientConfig) *client.Server
}

// newMCPHandler creates a new MCP handler (private, for testing)
func newMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	userManager UserMCPManager,
	userTokenStore UserTokenGetter,
	setupBaseURL string,
	info mcp.Implementation,
	newMCPServerFunc func(name, version, baseURL string, config *config.MCPClientConfig) *client.Server,
) *MCPHandler {
	return &MCPHandler{
		serverName:       serverName,
		serverConfig:     serverConfig,
		userManager:      userManager,
		userTokenStore:   userTokenStore,
		setupBaseURL:     setupBaseURL,
		info:             info,
		newMCPServerFunc: newMCPServerFunc,
	}
}

// NewMCPHandler creates a new MCP handler with default implementations (public)
func NewMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	userManager *client.UserMCPManager,
	oauthServer *oauth.Server,
	setupBaseURL string,
	info mcp.Implementation,
) *MCPHandler {
	var userTokenStore UserTokenGetter
	if oauthServer != nil {
		userTokenStore = oauthServer.GetUserTokenStore()
	}
	
	return newMCPHandler(
		serverName,
		serverConfig,
		userManager,
		userTokenStore,
		setupBaseURL,
		info,
		client.NewMCPServer, // default implementation
	)
}

// ServeHTTP handles incoming MCP requests
func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user email from context (set by OAuth middleware)
	// We use per-user instances for all services, even those that don't require user tokens
	userEmail, ok := oauth.GetUserFromContext(ctx)
	if !ok {
		internal.LogErrorWithFields("mcp", "No user email in context", map[string]interface{}{
			"service": h.serverName,
		})
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Determine if this server requires user tokens
	if h.serverConfig.RequiresUserToken {

		// Get user's token for this service
		userToken, err := h.userTokenStore.GetUserToken(ctx, userEmail, h.serverName)
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

		if isStdioServer(h.serverConfig) {
			// For stdio servers, we still need per-request instances but also need SSE bridging
			// Create a new client instance for each request
			mcpClient, err := h.userManager.CreateStdioInstance(ctx, userEmail, h.serverName, h.serverConfig, userToken)
			if err != nil {
				internal.LogErrorWithFields("mcp", "Failed to create stdio instance", map[string]interface{}{
					"error":   err.Error(),
					"user":    userEmail,
					"service": h.serverName,
				})
				http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
				return
			}
			defer mcpClient.Close()

			// Create temporary SSE server for this request
			server := h.newMCPServerFunc(h.serverName, "dev", h.setupBaseURL, h.serverConfig)
			
			// Connect client to server
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
			// For SSE servers, get or create a cached SSE server instance
			server, err := h.userManager.GetOrCreateSSEServer(ctx, userEmail, h.serverName, h.serverConfig, userToken, h.info, h.setupBaseURL)
			if err != nil {
				internal.LogErrorWithFields("mcp", "Failed to get/create SSE server", map[string]interface{}{
					"error":   err.Error(),
					"user":    userEmail,
					"service": h.serverName,
				})
				http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
				return
			}

			// Handle the SSE request using the cached server
			server.SSEServer.ServeHTTP(w, r)
		}
	} else {
		// For services that don't require user tokens, still use per-user instances for consistency
		// but with empty user token
		if isStdioServer(h.serverConfig) {
			// For stdio servers, create a new client instance for each request
			mcpClient, err := h.userManager.CreateStdioInstance(ctx, userEmail, h.serverName, h.serverConfig, "")
			if err != nil {
				internal.LogErrorWithFields("mcp", "Failed to create stdio instance", map[string]interface{}{
					"error":   err.Error(),
					"user":    userEmail,
					"service": h.serverName,
				})
				http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
				return
			}
			defer mcpClient.Close()

			// Create temporary SSE server for this request
			server := h.newMCPServerFunc(h.serverName, "dev", h.setupBaseURL, h.serverConfig)
			
			// Connect client to server
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
			// For SSE servers, get or create a cached SSE server instance (no user token)
			server, err := h.userManager.GetOrCreateSSEServer(ctx, userEmail, h.serverName, h.serverConfig, "", h.info, h.setupBaseURL)
			if err != nil {
				internal.LogErrorWithFields("mcp", "Failed to get/create SSE server", map[string]interface{}{
					"error":   err.Error(),
					"user":    userEmail,
					"service": h.serverName,
				})
				http.Error(w, "Failed to connect to service", http.StatusServiceUnavailable)
				return
			}

			// Handle the SSE request using the cached server
			server.SSEServer.ServeHTTP(w, r)
		}
	}
}


// isStdioServer determines if this is a stdio-based server
func isStdioServer(cfg *config.MCPClientConfig) bool {
	return cfg.TransportType == config.MCPClientTypeStdio || cfg.Command != ""
}