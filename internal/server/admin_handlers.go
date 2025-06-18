package server

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
)

// AdminHandlers handles the admin UI
type AdminHandlers struct {
	storage        storage.Storage
	config         *config.Config
	sessionManager *client.StdioSessionManager
	csrfTokens     sync.Map // Thread-safe CSRF token storage
}

// NewAdminHandlers creates a new admin handlers instance
func NewAdminHandlers(storage storage.Storage, config *config.Config, sessionManager *client.StdioSessionManager) *AdminHandlers {
	return &AdminHandlers{
		storage:        storage,
		config:         config,
		sessionManager: sessionManager,
	}
}

// generateCSRFToken creates a new CSRF token
func (h *AdminHandlers) generateCSRFToken() (string, error) {
	token := crypto.GenerateSecureToken()
	if token == "" {
		return "", fmt.Errorf("failed to generate CSRF token")
	}
	h.csrfTokens.Store(token, true)
	return token, nil
}

// validateCSRFToken checks if a CSRF token is valid
func (h *AdminHandlers) validateCSRFToken(token string) bool {
	if _, exists := h.csrfTokens.LoadAndDelete(token); exists {
		// One-time use via LoadAndDelete
		return true
	}
	return false
}

// DashboardHandler shows the admin dashboard
func (h *AdminHandlers) DashboardHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !auth.IsAdmin(userEmail, h.config.Proxy.Admin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get current tab from query param
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "users"
	}

	// Get message from query params
	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")

	// Load all data
	users, err := h.storage.GetAllUsers(r.Context())
	if err != nil {
		internal.LogErrorWithFields("admin", "Failed to get users", map[string]interface{}{
			"error": err.Error(),
		})
		users = []storage.UserInfo{} // Empty list on error
	}

	sessions, err := h.storage.GetActiveSessions(r.Context())
	if err != nil {
		internal.LogErrorWithFields("admin", "Failed to get sessions", map[string]interface{}{
			"error": err.Error(),
		})
		sessions = []storage.ActiveSession{} // Empty list on error
	}

	currentLogLevel := internal.GetLogLevel()

	// Generate CSRF token
	csrfToken, err := h.generateCSRFToken()
	if err != nil {
		internal.LogErrorWithFields("admin", "Failed to generate CSRF token", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Render page
	data := AdminPageData{
		UserEmail:   userEmail,
		ActiveTab:   tab,
		Users:       users,
		Sessions:    sessions,
		LogLevel:    currentLogLevel,
		CSRFToken:   csrfToken,
		Message:     message,
		MessageType: messageType,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminPageTemplate.Execute(w, data); err != nil {
		internal.LogErrorWithFields("admin", "Failed to render admin page", map[string]interface{}{
			"error": err.Error(),
		})
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// UserActionHandler handles user management actions
func (h *AdminHandlers) UserActionHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !auth.IsAdmin(userEmail, h.config.Proxy.Admin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate CSRF
	if !h.validateCSRFToken(r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	action := r.FormValue("action")
	targetEmail := r.FormValue("user_email")

	if targetEmail == "" {
		http.Error(w, "Missing user_email", http.StatusBadRequest)
		return
	}

	var message string
	var messageType string = "success"

	switch action {
	case "toggle":
		// Get current status
		users, err := h.storage.GetAllUsers(r.Context())
		if err != nil {
			message = "Failed to get user status"
			messageType = "error"
		} else {
			var currentEnabled bool
			for _, u := range users {
				if u.Email == targetEmail {
					currentEnabled = u.Enabled
					break
				}
			}
			// Toggle status
			if err := h.storage.UpdateUserStatus(r.Context(), targetEmail, !currentEnabled); err != nil {
				message = fmt.Sprintf("Failed to update user: %v", err)
				messageType = "error"
			} else {
				if currentEnabled {
					message = fmt.Sprintf("User %s disabled", targetEmail)
				} else {
					message = fmt.Sprintf("User %s enabled", targetEmail)
				}
			}
		}

	case "delete":
		if err := h.storage.DeleteUser(r.Context(), targetEmail); err != nil {
			message = fmt.Sprintf("Failed to delete user: %v", err)
			messageType = "error"
		} else {
			message = fmt.Sprintf("User %s deleted", targetEmail)
		}

	case "promote":
		if err := h.storage.SetUserAdmin(r.Context(), targetEmail, true); err != nil {
			message = fmt.Sprintf("Failed to promote user: %v", err)
			messageType = "error"
		} else {
			message = fmt.Sprintf("User %s promoted to admin", targetEmail)
		}

	case "demote":
		// Prevent demoting yourself
		if targetEmail == userEmail {
			message = "Cannot demote yourself"
			messageType = "error"
		} else {
			if err := h.storage.SetUserAdmin(r.Context(), targetEmail, false); err != nil {
				message = fmt.Sprintf("Failed to demote user: %v", err)
				messageType = "error"
			} else {
				message = fmt.Sprintf("User %s demoted from admin", targetEmail)
			}
		}

	default:
		message = "Unknown action"
		messageType = "error"
	}

	// Redirect back to admin page with message
	http.Redirect(w, r, fmt.Sprintf("/admin?tab=users&message=%s&type=%s", 
		url.QueryEscape(message), messageType), http.StatusSeeOther)
}

// SessionActionHandler handles session management actions
func (h *AdminHandlers) SessionActionHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !auth.IsAdmin(userEmail, h.config.Proxy.Admin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate CSRF
	if !h.validateCSRFToken(r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	action := r.FormValue("action")
	sessionID := r.FormValue("session_id")

	if sessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	var message string
	var messageType string = "success"

	switch action {
	case "revoke":
		// First get session details to revoke from session manager
		sessions, err := h.storage.GetActiveSessions(r.Context())
		if err == nil {
			for _, s := range sessions {
				if s.SessionID == sessionID {
					// Remove from session manager
					key := client.SessionKey{
						UserEmail:  s.UserEmail,
						ServerName: s.ServerName,
						SessionID:  s.SessionID,
					}
					h.sessionManager.RemoveSession(key)
					break
				}
			}
		}

		// Remove from storage
		if err := h.storage.RevokeSession(r.Context(), sessionID); err != nil {
			message = fmt.Sprintf("Failed to revoke session: %v", err)
			messageType = "error"
		} else {
			message = "Session revoked"
		}

	default:
		message = "Unknown action"
		messageType = "error"
	}

	// Redirect back to admin page with message
	http.Redirect(w, r, fmt.Sprintf("/admin?tab=sessions&message=%s&type=%s", 
		url.QueryEscape(message), messageType), http.StatusSeeOther)
}

// LoggingActionHandler handles logging configuration changes
func (h *AdminHandlers) LoggingActionHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !auth.IsAdmin(userEmail, h.config.Proxy.Admin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate CSRF
	if !h.validateCSRFToken(r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	logLevel := r.FormValue("log_level")
	if logLevel == "" {
		http.Error(w, "Missing log_level", http.StatusBadRequest)
		return
	}

	var message string
	var messageType string = "success"

	// Update log level
	if err := internal.SetLogLevel(logLevel); err != nil {
		message = fmt.Sprintf("Failed to set log level: %v", err)
		messageType = "error"
	} else {
		message = fmt.Sprintf("Log level changed to %s", logLevel)
		
		// Log the change at INFO level
		internal.LogInfoWithFields("admin", "Log level changed by admin", map[string]interface{}{
			"new_level": logLevel,
			"admin":     userEmail,
		})
	}

	// Redirect back to admin page with message
	http.Redirect(w, r, fmt.Sprintf("/admin?tab=logging&message=%s&type=%s", 
		url.QueryEscape(message), messageType), http.StatusSeeOther)
}

// AdminPageData represents the data for the admin page template
type AdminPageData struct {
	UserEmail   string
	ActiveTab   string
	Users       []storage.UserInfo
	Sessions    []storage.ActiveSession
	LogLevel    string
	CSRFToken   string
	Message     string
	MessageType string
}