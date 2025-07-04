package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
)

// ServiceAuthHandlers handles OAuth flows for external services
type ServiceAuthHandlers struct {
	oauthClient *auth.ServiceOAuthClient
	mcpServers  map[string]*config.MCPClientConfig
	storage     storage.Storage
}

// NewServiceAuthHandlers creates new service auth handlers
func NewServiceAuthHandlers(oauthClient *auth.ServiceOAuthClient, mcpServers map[string]*config.MCPClientConfig, storage storage.Storage) *ServiceAuthHandlers {
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

	// Start OAuth flow - service OAuth always returns to interstitial page
	authURL, err := h.oauthClient.StartOAuthFlow(
		r.Context(),
		userEmail,
		serviceName,
		serviceConfig,
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

		// Service OAuth errors always redirect back to interstitial page
		// This maintains user context in the upstream OAuth flow
		errorMsg := fmt.Sprintf("OAuth authorization failed: %s", errorParam)
		if errorDesc != "" {
			errorMsg = fmt.Sprintf("%s - %s", errorMsg, errorDesc)
		}

		// Redirect to interstitial page with error
		errorURL := fmt.Sprintf("/oauth/services?error=%s&service=%s&error_msg=%s",
			url.QueryEscape(errorParam),
			url.QueryEscape(serviceName),
			url.QueryEscape(errorMsg),
		)
		http.Redirect(w, r, errorURL, http.StatusFound)
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
	userEmail, err := h.oauthClient.HandleCallback(
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

		// Service OAuth callback errors always redirect back to interstitial page
		// This maintains user context in the upstream OAuth flow
		errorURL := fmt.Sprintf("/oauth/services?error=callback_failed&service=%s&error_msg=%s",
			url.QueryEscape(serviceName),
			url.QueryEscape(message),
		)
		http.Redirect(w, r, errorURL, http.StatusFound)
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

	// Service OAuth success always redirects back to interstitial page
	// This maintains user context in the upstream OAuth flow
	successURL := fmt.Sprintf("/oauth/services?message=%s&type=success",
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
