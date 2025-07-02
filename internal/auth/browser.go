package auth

import (
	"context"
	"encoding/json"
	"fmt"
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

// SSOMiddleware creates middleware for browser-based SSO authentication
func (s *Server) SSOMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for session cookie
			sessionValue, err := cookie.GetSession(r)
			if err != nil {
				// No cookie, redirect directly to Google OAuth
				state := s.generateBrowserState(r.URL.String())
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
				// Expired session
				log.LogDebug("Session expired for user %s", sessionData.Email)
				cookie.ClearSession(w)
				// Redirect directly to Google OAuth
				state := s.generateBrowserState(r.URL.String())
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
	// Generate random nonce
	nonce := crypto.GenerateSecureToken()

	// Create signed CSRF token: nonce + HMAC(nonce + returnURL)
	// This ensures the token is tied to the specific return URL
	data := nonce + ":" + returnURL
	signature := crypto.SignData(data, []byte(s.config.EncryptionKey))

	// Format: "browser:nonce:signature:returnURL"
	return fmt.Sprintf("browser:%s:%s:%s", nonce, signature, returnURL)
}
