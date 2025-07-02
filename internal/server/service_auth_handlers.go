package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/services"
	"github.com/dgellow/mcp-front/internal/storage"
)

// ServiceAuthHandlers handles OAuth flows for external services
type ServiceAuthHandlers struct {
	oauthClient *services.ServiceOAuthClient
	mcpServers  map[string]*config.MCPClientConfig
	storage     storage.Storage
}

// NewServiceAuthHandlers creates new service auth handlers
func NewServiceAuthHandlers(oauthClient *services.ServiceOAuthClient, mcpServers map[string]*config.MCPClientConfig, storage storage.Storage) *ServiceAuthHandlers {
	return &ServiceAuthHandlers{
		oauthClient: oauthClient,
		mcpServers:  mcpServers,
		storage:     storage,
	}
}

// ConnectHandler initiates OAuth flow for a service
func (h *ServiceAuthHandlers) ConnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	// Get authenticated user
	userEmail, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Authentication required")
		return
	}

	// Get service name from query
	serviceName := r.URL.Query().Get("service")
	if serviceName == "" {
		jsonwriter.WriteBadRequest(w, "Service name is required")
		return
	}

	// Get return URL
	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		returnURL = "/my/tokens"
	}

	// Validate service exists and supports OAuth
	serviceConfig, exists := h.mcpServers[serviceName]
	if !exists {
		jsonwriter.WriteNotFound(w, "Service not found")
		return
	}

	if !serviceConfig.RequiresUserToken ||
		serviceConfig.UserAuthentication == nil ||
		serviceConfig.UserAuthentication.Type != config.UserAuthTypeOAuth {
		jsonwriter.WriteBadRequest(w, "Service does not support OAuth")
		return
	}

	// Start OAuth flow
	authURL, err := h.oauthClient.StartOAuthFlow(
		r.Context(),
		userEmail,
		serviceName,
		serviceConfig,
		returnURL,
	)
	if err != nil {
		log.LogErrorWithFields("oauth_handlers", "Failed to start OAuth flow", map[string]any{
			"service": serviceName,
			"user":    userEmail,
			"error":   err.Error(),
		})
		jsonwriter.WriteInternalServerError(w, "Failed to start OAuth flow")
		return
	}

	// Redirect to authorization URL
	http.Redirect(w, r, authURL, http.StatusFound)
}

// CallbackHandler handles OAuth callbacks from services
func (h *ServiceAuthHandlers) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	// Extract service name from path: /oauth/callback/{service}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 {
		jsonwriter.WriteBadRequest(w, "Invalid callback path")
		return
	}
	serviceName := pathParts[2]
	if serviceName == "" {
		jsonwriter.WriteBadRequest(w, "Service name is required")
		return
	}

	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Handle OAuth errors
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.LogWarnWithFields("oauth_handlers", "OAuth error from provider", map[string]any{
			"service":     serviceName,
			"error":       errorParam,
			"description": errorDesc,
		})

		message := fmt.Sprintf("OAuth authorization failed: %s", errorParam)
		if errorDesc != "" {
			message = fmt.Sprintf("%s - %s", message, errorDesc)
		}
		redirectWithMessage(w, r, message, "error")
		return
	}

	if code == "" || state == "" {
		jsonwriter.WriteBadRequest(w, "Missing code or state parameter")
		return
	}

	// Validate service configuration
	serviceConfig, exists := h.mcpServers[serviceName]
	if !exists {
		jsonwriter.WriteNotFound(w, "Service not found")
		return
	}

	// Handle callback
	userEmail, returnURL, err := h.oauthClient.HandleCallback(
		r.Context(),
		serviceName,
		code,
		state,
		serviceConfig,
	)
	if err != nil {
		log.LogErrorWithFields("oauth_handlers", "Failed to handle OAuth callback", map[string]any{
			"service": serviceName,
			"error":   err.Error(),
		})

		// User-friendly error message
		message := "Failed to complete OAuth authorization"
		if strings.Contains(err.Error(), "invalid state") {
			message = "OAuth session expired. Please try again"
		}
		redirectWithMessage(w, r, message, "error")
		return
	}

	// Log successful connection
	log.LogInfoWithFields("oauth_handlers", "OAuth connection successful", map[string]any{
		"service": serviceName,
		"user":    userEmail,
	})

	// Display name for success message
	displayName := serviceName
	if serviceConfig.UserAuthentication != nil && serviceConfig.UserAuthentication.DisplayName != "" {
		displayName = serviceConfig.UserAuthentication.DisplayName
	}

	// Redirect with success message
	successURL := fmt.Sprintf("%s?message=%s&type=success",
		returnURL,
		strings.ReplaceAll(fmt.Sprintf("Successfully connected to %s", displayName), " ", "+"),
	)
	http.Redirect(w, r, successURL, http.StatusFound)
}

// DisconnectHandler revokes OAuth access for a service
func (h *ServiceAuthHandlers) DisconnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	// Get authenticated user
	userEmail, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Authentication required")
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		jsonwriter.WriteBadRequest(w, "Bad request")
		return
	}

	serviceName := r.FormValue("service")
	if serviceName == "" {
		jsonwriter.WriteBadRequest(w, "Service name is required")
		return
	}

	// Note: We don't validate CSRF for disconnect as it's less critical
	// and the user is already authenticated

	// Delete the token
	if err := h.storage.DeleteUserToken(r.Context(), userEmail, serviceName); err != nil {
		log.LogErrorWithFields("oauth_handlers", "Failed to delete OAuth token", map[string]any{
			"service": serviceName,
			"user":    userEmail,
			"error":   err.Error(),
		})
		jsonwriter.WriteInternalServerError(w, "Failed to disconnect")
		return
	}

	log.LogInfoWithFields("oauth_handlers", "OAuth disconnection successful", map[string]any{
		"service": serviceName,
		"user":    userEmail,
	})

	// Get display name
	displayName := serviceName
	if serviceConfig, exists := h.mcpServers[serviceName]; exists {
		if serviceConfig.UserAuthentication != nil && serviceConfig.UserAuthentication.DisplayName != "" {
			displayName = serviceConfig.UserAuthentication.DisplayName
		}
	}

	redirectWithMessage(w, r, fmt.Sprintf("Disconnected from %s", displayName), "success")
}
