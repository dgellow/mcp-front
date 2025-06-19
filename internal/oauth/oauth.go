package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

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
	key := []byte(config.EncryptionKey)
	sessionEncryptor, err := crypto.NewEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create session encryptor: %w", err)
	}
	internal.Logf("Session encryptor initialized for browser SSO")

	// Create auth service (business logic)
	authService, err := newAuthService(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	// Use provided JWT secret or generate a secure one
	var secret []byte
	if config.JWTSecret != "" {
		secret = []byte(config.JWTSecret)
		// Validate JWT secret length for HMAC-SHA512/256
		if len(secret) < 32 {
			return nil, fmt.Errorf("JWT secret must be at least 32 bytes long for security, got %d bytes", len(secret))
		}
	} else {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		internal.LogWarn("Generated random JWT secret. Set JWT_SECRET env var for persistent tokens across restarts")
	}

	// Determine min parameter entropy based on environment
	minEntropy := 8 // Production default - enforce secure state parameters (8+ chars)
	internal.Logf("OAuth server initialization - MCP_FRONT_ENV=%s, isDevelopmentMode=%v", os.Getenv("MCP_FRONT_ENV"), internal.IsDevelopmentMode())
	if internal.IsDevelopmentMode() {
		minEntropy = 0 // Development mode - allow weak state parameters for buggy clients
		internal.LogWarn("MCP_FRONT_ENV=development - weak OAuth state parameters allowed for testing")
	}
	internal.Logf("OAuth MinParameterEntropy set to: %d", minEntropy)

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
		MinParameterEntropy:            minEntropy,
	}

	// Create OAuth 2.1 provider
	provider := compose.Compose(
		fositeConfig,
		store.GetMemoryStore(),
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(fositeConfig, secret, nil),
		},
		nil, // hasher
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	// Set default session duration if not configured
	if config.SessionDuration == 0 {
		config.SessionDuration = 24 * time.Hour
	}

	return &Server{
		provider:         provider,
		storage:          store,
		authService:      authService,
		config:           config,
		sessionEncryptor: sessionEncryptor,
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
			"client_secret_post",
		},
		"revocation_endpoint":    s.config.Issuer + "/revoke",
		"introspection_endpoint": s.config.Issuer + "/introspect",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		internal.LogErrorWithFields("oauth", "Failed to encode metadata response", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

// AuthorizeHandler handles OAuth 2.0 authorization requests
func (s *Server) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Debug log the incoming request
	internal.Logf("Authorization request: %s", r.URL.RawQuery)
	clientID := r.URL.Query().Get("client_id")
	scopes := r.URL.Query().Get("scope")
	redirectURI := r.URL.Query().Get("redirect_uri")
	stateParam := r.URL.Query().Get("state")
	internal.Logf("Client ID: %s, Requested scopes: %s", clientID, scopes)
	internal.Logf("Requested redirect_uri: %s", redirectURI)
	internal.Logf("State parameter: '%s' (length: %d)", stateParam, len(stateParam))

	// In development mode, generate a secure state parameter if missing
	// This works around bugs in OAuth clients like MCP Inspector
	if internal.IsDevelopmentMode() && len(stateParam) == 0 {
		generatedState := crypto.GenerateSecureToken()
		internal.LogWarn("Development mode: generating state parameter '%s' for buggy client", generatedState)
		q := r.URL.Query()
		q.Set("state", generatedState)
		r.URL.RawQuery = q.Encode()
		// Also update the form values
		if r.Form == nil {
			_ = r.ParseForm()
		}
		r.Form.Set("state", generatedState)
	}

	// Debug: Check what redirect URIs the client actually has
	if client, err := s.storage.GetClient(ctx, clientID); err == nil {
		internal.Logf("Client registered redirect URIs: %v", client.GetRedirectURIs())
	} else {
		internal.LogError("Client not found: %v", err)
	}

	// WORKAROUND: Claude.ai generates a single client ID per OAuth provider domain
	// and reuses it forever. If the client registration is lost (server restart,
	// storage cleared, etc), Claude.ai has no mechanism to detect this and re-register.
	// This auto-registers their client to prevent users from being permanently locked out.
	// TODO: Remove once Claude.ai implements proper client registration retry logic
	if clientID != "" &&
		(redirectURI == "https://claude.ai/api/mcp/auth_callback" ||
			strings.HasPrefix(redirectURI, "https://claude.ai/api/mcp/")) {

		if _, err := s.storage.GetClient(ctx, clientID); err != nil {
			internal.LogWarn("Auto-registering Claude.ai client %s", clientID)

			// Register Claude.ai's client with their parameters
			redirectURIs := []string{redirectURI}
			requestedScopes := strings.Fields(scopes)
			if len(requestedScopes) == 0 {
				requestedScopes = []string{"read", "write"}
			}

			s.storage.CreateClient(clientID, redirectURIs, requestedScopes, s.config.Issuer)
		}
	}

	// Parse and validate the authorization request
	ar, err := s.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		internal.LogError("Authorization request error: %v", err)
		s.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	// Generate state for Google OAuth flow
	state := crypto.GenerateSecureToken()
	s.storage.StoreAuthorizeRequest(state, ar)

	// Redirect to Google OAuth
	googleURL := s.authService.googleAuthURL(state)
	internal.Logf("Redirecting to Google OAuth URL: %s", googleURL)

	http.Redirect(w, r, googleURL, http.StatusFound)
}

// GoogleCallbackHandler handles the callback from Google OAuth
func (s *Server) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		internal.LogError("Google OAuth error: %s - %s", errMsg, errDesc)
		http.Error(w, fmt.Sprintf("Authentication failed: %s", errMsg), http.StatusBadRequest)
		return
	}

	if state == "" || code == "" {
		internal.LogError("Missing state or code in callback")
		http.Error(w, "Invalid callback parameters", http.StatusBadRequest)
		return
	}

	// Check if this is a browser SSO flow
	var ar fosite.AuthorizeRequester
	var isBrowserFlow bool
	var returnURL string

	if strings.HasPrefix(state, "browser:") {
		// Browser SSO flow - validate signature and extract return URL
		isBrowserFlow = true
		// Format: "browser:nonce:signature:returnURL"
		parts := strings.SplitN(state, ":", 4)
		if len(parts) != 4 {
			internal.LogError("Invalid browser state format: %s", state)
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}
		// parts[0] = "browser", parts[1] = nonce, parts[2] = signature, parts[3] = return URL
		nonce := parts[1]
		signature := parts[2]
		returnURL = parts[3]

		// Validate HMAC signature
		data := nonce + ":" + returnURL
		if !crypto.ValidateSignedData(data, signature, []byte(s.config.EncryptionKey)) {
			internal.LogError("Invalid CSRF signature in browser flow")
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}
	} else {
		// OAuth client flow - retrieve stored authorize request
		var found bool
		ar, found = s.storage.GetAuthorizeRequest(state)
		if !found {
			internal.LogError("Invalid or expired state: %s", state)
			http.Error(w, "Invalid or expired authorization request", http.StatusBadRequest)
			return
		}
	}

	// Exchange code for token with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	token, err := s.authService.exchangeCodeForToken(ctx, code)
	if err != nil {
		internal.LogError("Google token exchange error: %v", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Validate user and get user info
	userInfo, err := s.authService.validateUser(ctx, token)
	if err != nil {
		internal.LogError("User validation error: %v", err)
		http.Error(w, "Access denied: user validation failed", http.StatusForbidden)
		return
	}
	internal.Logf("User validated successfully: %s", userInfo.Email)

	// Handle browser SSO flow
	if isBrowserFlow {
		// Set session cookie
		if err := s.setBrowserSessionCookie(w, userInfo.Email); err != nil {
			internal.LogError("Failed to set browser session cookie: %v", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		// Redirect to the original URL
		internal.Logf("Browser SSO successful for %s, redirecting to %s", userInfo.Email, returnURL)
		http.Redirect(w, r, returnURL, http.StatusFound)
		return
	}

	// Handle OAuth client flow
	// Create session with user info
	session := NewSession(userInfo)
	internal.Logf("Session created for user: %s", userInfo.Email)

	internal.Logf("Creating authorize response for client: %s", ar.GetClient().GetID())
	response, err := s.provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		internal.LogError("Failed to create authorize response: %v (type: %T)", err, err)
		// Log more details about the error
		if fositeErr, ok := err.(*fosite.RFC6749Error); ok {
			internal.LogError("Fosite error details - Code: %s, Description: %s, Debug: %s",
				fositeErr.ErrorField, fositeErr.DescriptionField, fositeErr.DebugField)
		}
		s.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	// Continue with normal OAuth flow
	s.provider.WriteAuthorizeResponse(w, ar, response)
}

// TokenHandler handles OAuth 2.0 token requests
func (s *Server) TokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Create session for the token exchange
	// Note: We create our custom Session type here, and fosite will populate it
	// with the session data from the authorization code during NewAccessRequest
	session := &Session{DefaultSession: &fosite.DefaultSession{}}

	// Handle token request - this retrieves the session from the authorization code
	accessRequest, err := s.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		internal.LogError("Access request error: %v", err)
		s.provider.WriteAccessError(w, accessRequest, err)
		return
	}

	// At this point, accessRequest.GetSession() contains the session data from
	// the authorization phase (including our custom UserInfo). Fosite handles
	// the session propagation internally when creating the access token.

	// Generate tokens
	response, err := s.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		internal.LogError("Access response error: %v", err)
		s.provider.WriteAccessError(w, accessRequest, err)
		return
	}

	// Write token response
	s.provider.WriteAccessResponse(w, accessRequest, response)
}

// buildClientRegistrationResponse creates the registration response for a client
func (s *Server) buildClientRegistrationResponse(client *fosite.DefaultClient, tokenEndpointAuthMethod string, clientSecret string) map[string]interface{} {
	response := map[string]interface{}{
		"client_id":                  client.GetID(),
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              client.GetRedirectURIs(),
		"grant_types":                client.GetGrantTypes(),
		"response_types":             client.GetResponseTypes(),
		"scope":                      strings.Join(client.GetScopes(), " "), // Space-separated string
		"token_endpoint_auth_method": tokenEndpointAuthMethod,
	}

	// Include client_secret only for confidential clients
	if clientSecret != "" {
		response["client_secret"] = clientSecret
	}

	return response
}

// RegisterHandler handles dynamic client registration (RFC 7591)
func (s *Server) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	internal.Logf("Register handler called: %s %s", r.Method, r.URL.Path)

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
		internal.LogError("Client request parsing error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if client requests client_secret_post authentication
	tokenEndpointAuthMethod := "none"
	var client *fosite.DefaultClient
	var plaintextSecret string
	clientID := crypto.GenerateSecureToken()

	if authMethod, ok := metadata["token_endpoint_auth_method"].(string); ok && authMethod == "client_secret_post" {
		// Generate and hash secret for confidential client
		generatedSecret, err := crypto.GenerateClientSecret()
		if err != nil {
			internal.LogError("Failed to generate client secret: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		hashedSecret, err := crypto.HashClientSecret(generatedSecret)
		if err != nil {
			internal.LogError("Failed to hash client secret: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		client = s.storage.CreateConfidentialClient(clientID, hashedSecret, redirectURIs, scopes, s.config.Issuer)
		tokenEndpointAuthMethod = "client_secret_post"
		plaintextSecret = generatedSecret // Save for response
	} else {
		// Create public client (default behavior)
		client = s.storage.CreateClient(clientID, redirectURIs, scopes, s.config.Issuer)
	}

	// Build response using helper function
	response := s.buildClientRegistrationResponse(client, tokenEndpointAuthMethod, plaintextSecret)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogErrorWithFields("oauth", "Failed to encode register response", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

// DebugClientsHandler shows all registered clients (for debugging)
func (s *Server) DebugClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients := make(map[string]interface{})

	// Get all clients thread-safely
	allClients := s.storage.GetAllClients()
	for clientID, client := range allClients {
		clients[clientID] = map[string]interface{}{
			"redirect_uris":  client.GetRedirectURIs(),
			"scopes":         client.GetScopes(),
			"grant_types":    client.GetGrantTypes(),
			"response_types": client.GetResponseTypes(),
		}
	}

	response := map[string]interface{}{
		"total_clients": len(clients),
		"clients":       clients,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		internal.LogErrorWithFields("oauth", "Failed to encode debug response", map[string]interface{}{
			"error": err.Error(),
		})
	}
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

// logf is a simple logging helper
