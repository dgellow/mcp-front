package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/interfaces"
	"github.com/dgellow/mcp-front/internal/oauth"
)

// TokenHandlers handles the web UI for token management
type TokenHandlers struct {
	tokenStore   interfaces.UserTokenStore
	mcpServers   map[string]*config.MCPClientConfig
	csrfTokens   sync.Map // Thread-safe CSRF token storage
	oauthEnabled bool
}

// NewTokenHandlers creates a new token handlers instance
func NewTokenHandlers(tokenStore interfaces.UserTokenStore, mcpServers map[string]*config.MCPClientConfig, oauthEnabled bool) *TokenHandlers {
	return &TokenHandlers{
		tokenStore:   tokenStore,
		mcpServers:   mcpServers,
		oauthEnabled: oauthEnabled,
	}
}

// generateCSRFToken creates a new CSRF token
func (h *TokenHandlers) generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(b)
	h.csrfTokens.Store(token, true)
	return token, nil
}

// validateCSRFToken checks if a CSRF token is valid
func (h *TokenHandlers) validateCSRFToken(token string) bool {
	if _, exists := h.csrfTokens.LoadAndDelete(token); exists {
		// One-time use via LoadAndDelete
		return true
	}
	return false
}

// ListTokensHandler shows the token management page
func (h *TokenHandlers) ListTokensHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userEmail, ok := oauth.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")

	// Build service list
	var services []ServiceTokenData

	for name, config := range h.mcpServers {
		service := ServiceTokenData{
			Name:        name,
			DisplayName: name,
		}

		// Determine authentication type
		if config.RequiresUserToken {
			service.RequiresToken = true
			service.Instructions = fmt.Sprintf("Please create a %s API token", name)

			if config.TokenSetup != nil {
				if config.TokenSetup.DisplayName != "" {
					service.DisplayName = config.TokenSetup.DisplayName
				}
				if config.TokenSetup.Instructions != "" {
					service.Instructions = config.TokenSetup.Instructions
				}
				service.HelpURL = config.TokenSetup.HelpURL
				service.TokenFormat = config.TokenSetup.TokenFormat
			}

			_, err := h.tokenStore.GetUserToken(r.Context(), userEmail, name)
			service.HasToken = err == nil
		} else {
			// Determine if it's OAuth authenticated or uses bearer tokens
			if h.oauthEnabled {
				service.AuthType = "oauth"
			} else if config.Options != nil && len(config.Options.AuthTokens) > 0 {
				service.AuthType = "bearer"
			} else {
				service.AuthType = "none"
			}
		}

		services = append(services, service)
	}

	// Generate CSRF token
	csrfToken, err := h.generateCSRFToken()
	if err != nil {
		internal.LogErrorWithFields("token", "Failed to generate CSRF token", map[string]interface{}{
			"error": err.Error(),
			"user":  userEmail,
		})
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Render page
	data := TokenPageData{
		UserEmail:   userEmail,
		Services:    services,
		CSRFToken:   csrfToken,
		Message:     message,
		MessageType: messageType,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tokenPageTemplate.Execute(w, data); err != nil {
		internal.LogErrorWithFields("token", "Failed to render token page", map[string]interface{}{
			"error": err.Error(),
			"user":  userEmail,
		})
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// SetTokenHandler handles token submission
func (h *TokenHandlers) SetTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userEmail, ok := oauth.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate CSRF token
	csrfToken := r.FormValue("csrf_token")
	if !h.validateCSRFToken(csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	serviceName := r.FormValue("service")
	if serviceName == "" {
		http.Error(w, "Service name is required", http.StatusBadRequest)
		return
	}

	// Validate service exists and requires user token
	serviceConfig, exists := h.mcpServers[serviceName]
	if !exists || !serviceConfig.RequiresUserToken {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		redirectWithMessage(w, r, "Token cannot be empty", "error")
		return
	}

	// Security: Limit token length to prevent DoS
	const maxTokenLength = 4096
	if len(token) > maxTokenLength {
		redirectWithMessage(w, r, "Token is too long", "error")
		return
	}

	if serviceConfig.TokenSetup != nil && serviceConfig.TokenSetup.CompiledRegex != nil {
		if !serviceConfig.TokenSetup.CompiledRegex.MatchString(token) {
			var helpMsg string
			displayName := serviceName
			if serviceConfig.TokenSetup.DisplayName != "" {
				displayName = serviceConfig.TokenSetup.DisplayName
			}

			// Provide specific error messages based on common token patterns
			switch {
			case serviceConfig.TokenSetup.TokenFormat == "^[A-Za-z0-9_-]+$":
				helpMsg = fmt.Sprintf("%s token must contain only letters, numbers, underscores, and hyphens", displayName)
			case strings.Contains(serviceConfig.TokenSetup.TokenFormat, "^[A-Fa-f0-9]{64}$"):
				helpMsg = fmt.Sprintf("%s token must be a 64-character hexadecimal string", displayName)
			case strings.Contains(serviceConfig.TokenSetup.TokenFormat, "Bearer "):
				helpMsg = fmt.Sprintf("%s token should not include 'Bearer' prefix - just the token value", displayName)
			default:
				if serviceConfig.TokenSetup.HelpURL != "" {
					helpMsg = fmt.Sprintf("Invalid %s token format. Please check the required format at %s",
						displayName, serviceConfig.TokenSetup.HelpURL)
				} else {
					helpMsg = fmt.Sprintf("Invalid %s token format. Expected pattern: %s",
						displayName, serviceConfig.TokenSetup.TokenFormat)
				}
			}
			redirectWithMessage(w, r, helpMsg, "error")
			return
		}
	}

	if err := h.tokenStore.SetUserToken(r.Context(), userEmail, serviceName, token); err != nil {
		internal.LogErrorWithFields("token", "Failed to store token", map[string]interface{}{
			"error":   err.Error(),
			"user":    userEmail,
			"service": serviceName,
		})
		redirectWithMessage(w, r, "Failed to save token", "error")
		return
	}

	displayName := serviceName
	if serviceConfig.TokenSetup != nil && serviceConfig.TokenSetup.DisplayName != "" {
		displayName = serviceConfig.TokenSetup.DisplayName
	}

	internal.LogInfoWithFields("token", "User configured token", map[string]interface{}{
		"user":    userEmail,
		"service": serviceName,
		"action":  "set_token",
	})
	redirectWithMessage(w, r, fmt.Sprintf("Token for %s saved successfully", displayName), "success")
}

// DeleteTokenHandler handles token deletion
func (h *TokenHandlers) DeleteTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userEmail, ok := oauth.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate CSRF token
	csrfToken := r.FormValue("csrf_token")
	if !h.validateCSRFToken(csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	serviceName := r.FormValue("service")
	if serviceName == "" {
		http.Error(w, "Service name is required", http.StatusBadRequest)
		return
	}

	serviceConfig, exists := h.mcpServers[serviceName]
	if !exists {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	if err := h.tokenStore.DeleteUserToken(r.Context(), userEmail, serviceName); err != nil {
		internal.LogErrorWithFields("token", "Failed to delete token", map[string]interface{}{
			"error":   err.Error(),
			"user":    userEmail,
			"service": serviceName,
		})
		redirectWithMessage(w, r, "Failed to delete token", "error")
		return
	}

	displayName := serviceName
	if serviceConfig.TokenSetup != nil && serviceConfig.TokenSetup.DisplayName != "" {
		displayName = serviceConfig.TokenSetup.DisplayName
	}

	internal.LogInfoWithFields("token", "User deleted token", map[string]interface{}{
		"user":    userEmail,
		"service": serviceName,
		"action":  "delete_token",
	})
	redirectWithMessage(w, r, fmt.Sprintf("Token for %s removed", displayName), "success")
}

// redirectWithMessage redirects back to the token list page with a message
func redirectWithMessage(w http.ResponseWriter, r *http.Request, message, messageType string) {
	http.Redirect(w, r, fmt.Sprintf("/my/tokens?message=%s&type=%s",
		strings.ReplaceAll(message, " ", "+"), messageType), http.StatusSeeOther)
}
