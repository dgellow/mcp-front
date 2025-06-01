package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

// Server wraps fosite.OAuth2Provider with clean architecture
type Server struct {
	provider    fosite.OAuth2Provider
	storage     *Storage
	authService *authService
	config      Config
}

// Config holds OAuth server configuration
type Config struct {
	Issuer             string
	TokenTTL           time.Duration
	AllowedDomains     []string
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string
	JWTSecret          string // Should be provided via environment variable
}

// NewServer creates a new OAuth 2.1 server
func NewServer(config Config) (*Server, error) {
	// Create storage (data layer)
	storage := newStorage()

	// Create auth service (business logic)
	authService, err := newAuthService(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	// Use provided JWT secret or generate a secure one
	var secret []byte
	if config.JWTSecret != "" {
		secret = []byte(config.JWTSecret)
	} else {
		// Generate a cryptographically secure random secret
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		logf("WARNING: Generated random JWT secret. Set JWT_SECRET env var for persistent tokens across restarts")
	}

	// Create fosite configuration
	fositeConfig := &compose.Config{
		AccessTokenLifespan:            config.TokenTTL,
		RefreshTokenLifespan:           24 * time.Hour,
		AuthorizeCodeLifespan:          10 * time.Minute,
		TokenURL:                       config.Issuer + "/token",
		ScopeStrategy:                  fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
	}

	// Create OAuth 2.1 provider
	provider := compose.Compose(
		fositeConfig,
		storage.MemoryStore,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(fositeConfig, secret, nil),
		},
		nil, // hasher
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
	)

	return &Server{
		provider:    provider,
		storage:     storage,
		authService: authService,
		config:      config,
	}, nil
}

// WellKnownHandler serves OAuth 2.0 Authorization Server Metadata (RFC 8414)
func (s *Server) WellKnownHandler(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]interface{}{
		"issuer":                 s.config.Issuer,
		"authorization_endpoint": s.config.Issuer + "/authorize",
		"token_endpoint":         s.config.Issuer + "/token",
		"registration_endpoint":  s.config.Issuer + "/register",
		"scopes_supported": []string{
			"read",
			"write",
		},
		"response_types_supported": []string{
			"code",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		"code_challenge_methods_supported": []string{
			"S256",
		},
		"token_endpoint_auth_methods_supported": []string{
			"none",
		},
		"revocation_endpoint": s.config.Issuer + "/revoke",
		"introspection_endpoint": s.config.Issuer + "/introspect",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// AuthorizeHandler handles OAuth 2.0 authorization requests
func (s *Server) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Debug log the incoming request
	logf("Authorization request: %s", r.URL.RawQuery)
	clientID := r.URL.Query().Get("client_id")
	scopes := r.URL.Query().Get("scope")
	redirectURI := r.URL.Query().Get("redirect_uri")
	logf("Client ID: %s, Requested scopes: %s", clientID, scopes)
	logf("Requested redirect_uri: %s", redirectURI)
	
	// Debug: Check what redirect URIs the client actually has
	if client, err := s.storage.GetClient(ctx, clientID); err == nil {
		logf("Client registered redirect URIs: %v", client.GetRedirectURIs())
	} else {
		logf("Client not found: %v", err)
	}

	// Parse and validate the authorization request
	ar, err := s.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		logf("Authorization request error: %v", err)
		s.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	// Generate state for Google OAuth flow
	state := s.storage.generateState()
	s.storage.storeAuthorizeRequest(state, ar)

	// Redirect to Google OAuth
	googleURL := s.authService.googleAuthURL(state)

	http.Redirect(w, r, googleURL, http.StatusFound)
}

// GoogleCallbackHandler handles the callback from Google OAuth
func (s *Server) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get state and code from query params
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	
	// Check for errors from Google
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		logf("Google OAuth error: %s - %s", errMsg, errDesc)
		http.Error(w, fmt.Sprintf("Authentication failed: %s", errMsg), http.StatusBadRequest)
		return
	}

	if state == "" || code == "" {
		logf("Missing state or code in callback")
		http.Error(w, "Invalid callback parameters", http.StatusBadRequest)
		return
	}

	// Retrieve original authorize request
	ar, found := s.storage.getAuthorizeRequest(state)
	if !found {
		logf("Invalid or expired state: %s", state)
		http.Error(w, "Invalid or expired authorization request", http.StatusBadRequest)
		return
	}

	// Exchange code for token with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	token, err := s.authService.exchangeCodeForToken(ctx, code)
	if err != nil {
		logf("Google token exchange error: %v", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Validate user and get user info
	userInfo, err := s.authService.validateUser(ctx, token)
	if err != nil {
		logf("User validation error: %v", err)
		http.Error(w, "Access denied: user validation failed", http.StatusForbidden)
		return
	}

	// Create session with user info
	session := NewSession(userInfo)

	// Complete the authorization request
	response, err := s.provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		logf("Failed to create authorize response: %v", err)
		s.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	// Write the response (redirects back to client)
	s.provider.WriteAuthorizeResponse(w, ar, response)
}

// TokenHandler handles OAuth 2.0 token requests
func (s *Server) TokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Create session for the token
	session := &fosite.DefaultSession{}

	// Handle token request
	accessRequest, err := s.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		logf("Access request error: %v", err)
		s.provider.WriteAccessError(w, accessRequest, err)
		return
	}

	// Generate tokens
	response, err := s.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		logf("Access response error: %v", err)
		s.provider.WriteAccessError(w, accessRequest, err)
		return
	}

	// Write token response
	s.provider.WriteAccessResponse(w, accessRequest, response)
}

// RegisterHandler handles dynamic client registration (RFC 7591)
func (s *Server) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	logf("Register handler called: %s %s", r.Method, r.URL.Path)
	
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse client metadata
	var metadata map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse client request
	redirectURIs, scopes, err := s.authService.parseClientRequest(metadata)
	if err != nil {
		logf("Client request parsing error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate client ID and create client
	clientID := s.storage.generateState() // Reuse secure random generation
	client := s.storage.createClient(clientID, redirectURIs, scopes, s.config.Issuer)

	// Return client registration response
	response := map[string]interface{}{
		"client_id":                  client.GetID(),
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              client.GetRedirectURIs(),
		"grant_types":                client.GetGrantTypes(),
		"response_types":             client.GetResponseTypes(),
		"scope":                      strings.Join(client.GetScopes(), " "), // Space-separated string
		"token_endpoint_auth_method": "none",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DebugClientsHandler shows all registered clients (for debugging)
func (s *Server) DebugClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients := make(map[string]interface{})
	
	// Get all clients thread-safely
	allClients := s.storage.GetAllClients()
	for clientID, client := range allClients {
		clients[clientID] = map[string]interface{}{
			"redirect_uris":   client.GetRedirectURIs(),
			"scopes":         client.GetScopes(),
			"grant_types":    client.GetGrantTypes(),
			"response_types": client.GetResponseTypes(),
		}
	}
	
	response := map[string]interface{}{
		"total_clients": len(clients),
		"clients":      clients,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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

			// Validate token
			_, _, err := s.provider.IntrospectToken(ctx, token, fosite.AccessToken, &fosite.DefaultSession{})
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// logf is a simple logging helper
func logf(format string, args ...interface{}) {
	log.Printf("[%s] %s", time.Now().Format("2006-01-02 15:04:05.000-07:00"), fmt.Sprintf(format, args...))
}