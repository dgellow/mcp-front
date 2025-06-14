package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal/crypto"
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
			cookie, err := r.Cookie("mcp_session")
			if err != nil {
				// No cookie, redirect directly to Google OAuth
				// Store return URL in state parameter with a marker prefix
				state := "browser:" + r.URL.String()
				googleURL := s.authService.googleAuthURL(state)
				http.Redirect(w, r, googleURL, http.StatusFound)
				return
			}

			// Decrypt cookie
			encryptor, err := crypto.NewEncryptor([]byte(s.config.EncryptionKey))
			if err != nil {
				http.Error(w, "Server configuration error", http.StatusInternalServerError)
				return
			}

			decrypted, err := encryptor.Decrypt(cookie.Value)
			if err != nil {
				// Invalid cookie, redirect to OAuth
				http.SetCookie(w, &http.Cookie{Name: "mcp_session", MaxAge: -1}) // Clear bad cookie
				state := "browser:" + r.URL.String()
				googleURL := s.authService.googleAuthURL(state)
				http.Redirect(w, r, googleURL, http.StatusFound)
				return
			}

			// Parse session data
			var sessionData SessionData
			if err := json.Unmarshal([]byte(decrypted), &sessionData); err != nil {
				// Invalid format
				http.SetCookie(w, &http.Cookie{Name: "mcp_session", MaxAge: -1})
				http.Error(w, "Invalid session", http.StatusUnauthorized)
				return
			}

			// Check expiration
			if time.Now().After(sessionData.Expires) {
				// Expired session
				http.SetCookie(w, &http.Cookie{Name: "mcp_session", MaxAge: -1})
				// Redirect directly to Google OAuth
				state := "browser:" + r.URL.String()
				googleURL := s.authService.googleAuthURL(state)
				http.Redirect(w, r, googleURL, http.StatusFound)
				return
			}

			// Valid session, set user in context
			ctx := context.WithValue(r.Context(), userContextKey, sessionData.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// setBrowserSessionCookie sets an encrypted session cookie for browser-based authentication
func (s *Server) setBrowserSessionCookie(w http.ResponseWriter, userEmail string) error {
	encryptor, err := crypto.NewEncryptor([]byte(s.config.EncryptionKey))
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}

	// Create session data
	sessionData := SessionData{
		Email:   userEmail,
		Expires: time.Now().Add(24 * time.Hour),
	}

	jsonData, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	encrypted, err := encryptor.Encrypt(string(jsonData))
	if err != nil {
		return fmt.Errorf("failed to encrypt session: %w", err)
	}

	// Set secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "mcp_session",
		Value:    encrypted,
		Path:     "/",
		HttpOnly: true,
		Secure:   !isDevelopmentMode(), // Only require HTTPS in production
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})

	return nil
}
