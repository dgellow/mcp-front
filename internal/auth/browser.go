package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal/cookie"
	"github.com/dgellow/mcp-front/internal/crypto"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
)

// SessionData represents the data stored in the encrypted session cookie
type SessionData struct {
	Email   string    `json:"email"`
	Expires time.Time `json:"expires"`
}

// BrowserState represents the state parameter data for browser SSO
type BrowserState struct {
	Nonce     string `json:"nonce"`
	ReturnURL string `json:"return_url"`
}

// SSOMiddleware creates middleware for browser-based SSO authentication
func (s *Server) SSOMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for session cookie
			sessionValue, err := cookie.GetSession(r)
			if err != nil {
				// No cookie, redirect directly to OAuth
				state := s.generateBrowserState(r.URL.String())
				if state == "" {
					jsonwriter.WriteInternalServerError(w, "Failed to generate authentication state")
					return
				}
				googleURL := s.authService.GoogleAuthURL(state)
				http.Redirect(w, r, googleURL, http.StatusFound)
				return
			}

			// Decrypt cookie
			decrypted, err := s.sessionEncryptor.Decrypt(sessionValue)
			if err != nil {
				// Invalid cookie, redirect to OAuth
				log.LogDebug("Invalid session cookie: %v", err)
				cookie.ClearSession(w) // Clear bad cookie
				state := s.generateBrowserState(r.URL.String())
				googleURL := s.authService.GoogleAuthURL(state)
				http.Redirect(w, r, googleURL, http.StatusFound)
				return
			}

			// Parse session data
			var sessionData SessionData
			if err := json.Unmarshal([]byte(decrypted), &sessionData); err != nil {
				// Invalid format
				cookie.ClearSession(w)
				jsonwriter.WriteUnauthorized(w, "Invalid session")
				return
			}

			// Check expiration
			if time.Now().After(sessionData.Expires) {
				log.LogDebug("Session expired for user %s", sessionData.Email)
				cookie.ClearSession(w)
				// Redirect directly to Google OAuth
				state := s.generateBrowserState(r.URL.String())
				if state == "" {
					jsonwriter.WriteInternalServerError(w, "Failed to generate authentication state")
					return
				}
				googleURL := s.authService.GoogleAuthURL(state)
				http.Redirect(w, r, googleURL, http.StatusFound)
				return
			}

			// Valid session, set user in context
			ctx := context.WithValue(r.Context(), userContextKey, sessionData.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// generateBrowserState creates a secure state parameter for browser SSO
func (s *Server) generateBrowserState(returnURL string) string {
	state := BrowserState{
		Nonce:     crypto.GenerateSecureToken(),
		ReturnURL: returnURL,
	}

	token, err := s.browserStateToken.Sign(state)
	if err != nil {
		log.LogError("Failed to sign browser state: %v", err)
		// Return empty string to trigger auth failure - middleware will handle it
		return ""
	}
	return "browser:" + token
}
