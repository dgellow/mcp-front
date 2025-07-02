package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

// userContextKey is the context key for user email
const userContextKey contextKey = "user_email"

// GetUserFromContext extracts user email from context
func GetUserFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(userContextKey).(string)
	return email, ok
}

// GetUserContextKey returns the context key for user email (for testing)
func GetUserContextKey() contextKey {
	return userContextKey
}

// Server wraps fosite.OAuth2Provider with clean architecture
type Server struct {
	provider         fosite.OAuth2Provider
	storage          storage.Storage
	authService      *authService
	config           Config
	sessionEncryptor crypto.Encryptor // Created once for browser SSO performance
}

// Config holds OAuth server configuration
type Config struct {
	Issuer              string
	TokenTTL            time.Duration
	SessionDuration     time.Duration // Duration for browser session cookies (default: 24h)
	AllowedDomains      []string
	AllowedOrigins      []string // For CORS validation
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleRedirectURI   string
	JWTSecret           string // Should be provided via environment variable
	EncryptionKey       string // Should be provided via environment variable
	StorageType         string // "memory" or "firestore"
	GCPProjectID        string // Required for firestore storage
	FirestoreDatabase   string // Optional: Firestore database name (default: "(default)")
	FirestoreCollection string // Optional: Collection name for Firestore storage (default: "mcp_front_oauth_clients")
}

// NewServer creates a new OAuth 2.1 server
func NewServer(config Config, store storage.Storage) (*Server, error) {
	// Create session encryptor for browser SSO
	key := []byte(string(config.EncryptionKey))
	sessionEncryptor, err := crypto.NewEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create session encryptor: %w", err)
	}
	log.Logf("Session encryptor initialized for browser SSO")

	// Create auth service (business logic)
	authService, err := newAuthService(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	// Use provided JWT secret or generate a secure one
	var secret []byte
	if config.JWTSecret != "" {
		secret = []byte(string(config.JWTSecret))
		// Validate JWT secret length for HMAC-SHA512/256
		if len(secret) < 32 {
			return nil, fmt.Errorf("JWT secret must be at least 32 bytes long for security, got %d bytes", len(secret))
		}
	} else {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		log.LogWarn("Generated random JWT secret. Set JWT_SECRET env var for persistent tokens across restarts")
	}

	// Determine min parameter entropy based on environment
	minEntropy := 8 // Production default - enforce secure state parameters (8+ chars)
	log.Logf("OAuth server initialization - MCP_FRONT_ENV=%s, isDevelopmentMode=%v", os.Getenv("MCP_FRONT_ENV"), internal.IsDevelopmentMode())
	if internal.IsDevelopmentMode() {
		minEntropy = 0 // Development mode - allow empty state parameters
		log.LogWarn("Development mode enabled - OAuth security checks relaxed (state parameter entropy: %d)", minEntropy)
	}

	// Configure fosite
	oauthConfig := &compose.Config{
		AccessTokenLifespan:      config.TokenTTL,
		RefreshTokenLifespan:     config.TokenTTL * 2,
		AuthorizeCodeLifespan:    10 * time.Minute,
		MinParameterEntropy:      minEntropy,
		EnforcePKCE:              true,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		HashCost:                 12,
	}

	// Create provider using compose
	provider := compose.ComposeAllEnabled(
		oauthConfig,
		store,
		secret,
		nil, // RSA key not needed for our use case
	)

	return &Server{
		provider:         provider,
		storage:          store,
		authService:      authService,
		config:           config,
		sessionEncryptor: sessionEncryptor,
	}, nil
}

// GetProvider returns the fosite OAuth2Provider
func (s *Server) GetProvider() fosite.OAuth2Provider {
	return s.provider
}

// GetStorage returns the storage instance
func (s *Server) GetStorage() storage.Storage {
	return s.storage
}

// GetAuthService returns the auth service
func (s *Server) GetAuthService() *authService {
	return s.authService
}

// GetConfig returns the server configuration
func (s *Server) GetConfig() Config {
	return s.config
}

// GetSessionEncryptor returns the session encryptor
func (s *Server) GetSessionEncryptor() crypto.Encryptor {
	return s.sessionEncryptor
}

// ValidateTokenMiddleware creates middleware that validates OAuth tokens
func (s *Server) ValidateTokenMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract token from Authorization header
			auth := r.Header.Get("Authorization")
			if auth == "" {
				http.Error(w, "Missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(auth, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			token := parts[1]

			// Validate token and extract session
			// IMPORTANT: Fosite's IntrospectToken behavior is non-intuitive:
			// - The session parameter passed to IntrospectToken is NOT populated with data
			// - This is documented fosite behavior, not a bug
			// - The actual session data must be retrieved from the returned AccessRequester
			// See: https://github.com/ory/fosite/issues/256
			session := &Session{DefaultSession: &fosite.DefaultSession{}}
			_, accessRequest, err := s.provider.IntrospectToken(ctx, token, fosite.AccessToken, session)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Get the actual session from the access request (not the input session parameter)
			// This is the correct way to retrieve session data after token introspection
			var userEmail string
			if accessRequest != nil {
				if reqSession, ok := accessRequest.GetSession().(*Session); ok {
					if reqSession.UserInfo != nil && reqSession.UserInfo.Email != "" {
						userEmail = reqSession.UserInfo.Email
					}
				}
			}

			// Pass user info through context
			if userEmail != "" {
				ctx = context.WithValue(ctx, userContextKey, userEmail)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
