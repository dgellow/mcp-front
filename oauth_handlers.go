package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"golang.org/x/oauth2"
)

// OAuthServer wraps fosite.OAuth2Provider with our custom storage
type OAuthServer struct {
	provider fosite.OAuth2Provider
	storage  *GCPIAMStorage
	config   *OAuthConfig
}

// NewOAuthServer creates a new OAuth 2.1 server with GCP IAM integration
func NewOAuthServer(config *OAuthConfig) (*OAuthServer, error) {
	gcpStorage, err := NewGCPIAMStorage(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Generate RSA key for JWT signing
	secret := []byte("32-byte-long-secret-for-signing!!")

	// Create fosite configuration
	fositeConfig := &compose.Config{
		AccessTokenLifespan:      config.TokenTTL.ToDuration(),
		RefreshTokenLifespan:     24 * time.Hour,
		AuthorizeCodeLifespan:    10 * time.Minute,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	// Create OAuth 2.1 provider
	provider := compose.Compose(
		fositeConfig,
		gcpStorage.MemoryStore,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(fositeConfig, secret, nil),
		},
		nil, // hasher
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
	)

	return &OAuthServer{
		provider: provider,
		storage:  gcpStorage,
		config:   config,
	}, nil
}

// ServerMetadata represents OAuth 2.1 authorization server metadata
type ServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	PKCERequired                      bool     `json:"pkce_required"`
}

// WellKnownHandler serves OAuth 2.1 authorization server metadata
func (s *OAuthServer) WellKnownHandler(w http.ResponseWriter, r *http.Request) {
	metadata := ServerMetadata{
		Issuer:                 s.config.Issuer,
		AuthorizationEndpoint:  s.config.Issuer + "/authorize",
		TokenEndpoint:          s.config.Issuer + "/token",
		RegistrationEndpoint:   s.config.Issuer + "/register",
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},
		SubjectTypesSupported: []string{"public"},
		ScopesSupported:       []string{"read", "write"},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none", // For public clients with PKCE
		},
		CodeChallengeMethodsSupported: []string{"S256"},
		PKCERequired:                  true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// AuthorizeHandler handles OAuth 2.1 authorization requests
func (s *OAuthServer) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and validate the authorization request
	ar, err := s.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		logf("Authorization request error: %v", err)
		s.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	// Generate state for Google OAuth flow
	state := s.storage.GenerateState()
	s.storage.StoreAuthorizeRequest(state, ar)

	// Redirect to Google OAuth
	googleURL := s.storage.googleOAuth.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
	)

	http.Redirect(w, r, googleURL, http.StatusFound)
}

// GoogleCallbackHandler handles the callback from Google OAuth
func (s *OAuthServer) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check for error from Google
	if errorCode := r.URL.Query().Get("error"); errorCode != "" {
		errorDesc := r.URL.Query().Get("error_description")
		logf("Google OAuth error: %s - %s", errorCode, errorDesc)
		http.Error(w, fmt.Sprintf("OAuth error: %s", errorDesc), http.StatusBadRequest)
		return
	}

	// Extract state and code from callback
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" {
		logf("Missing state parameter in OAuth callback")
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	if code == "" {
		logf("Missing code parameter in OAuth callback")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Retrieve original authorize request
	ar, found := s.storage.GetAuthorizeRequest(state)
	if !found {
		logf("Invalid or expired state: %s", state)
		http.Error(w, "Invalid or expired authorization request", http.StatusBadRequest)
		return
	}

	// Exchange code for Google token with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	token, err := s.storage.googleOAuth.Exchange(ctx, code)
	if err != nil {
		logf("Google token exchange error: %v", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Validate Google token and get user info
	userInfo, err := s.storage.ValidateGoogleToken(ctx, token)
	if err != nil {
		logf("Google token validation error: %v", err)
		http.Error(w, "Access denied: user validation failed", http.StatusForbidden)
		return
	}

	// Create session with user info
	session := NewCustomSession(userInfo)

	// Complete OAuth 2.1 authorization flow
	response, err := s.provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		logf("Authorization response error: %v", err)
		s.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	logf("Successful OAuth flow for user: %s", userInfo.Email)
	s.provider.WriteAuthorizeResponse(w, ar, response)
}

// TokenHandler handles OAuth 2.1 token requests
func (s *OAuthServer) TokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Create access token session
	session := &CustomSession{DefaultSession: &fosite.DefaultSession{}}

	// Handle token request
	accessRequest, err := s.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		logf("Access request error: %v", err)
		s.provider.WriteAccessError(w, accessRequest, err)
		return
	}

	// Create access response
	response, err := s.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		logf("Access response error: %v", err)
		s.provider.WriteAccessError(w, accessRequest, err)
		return
	}

	s.provider.WriteAccessResponse(w, accessRequest, response)
}

// RegisterHandler handles dynamic client registration (RFC 7591)
func (s *OAuthServer) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Parse client metadata
	var metadata map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Create client
	client, err := s.storage.CreateClient(ctx, metadata)
	if err != nil {
		logf("Client creation error: %v", err)
		http.Error(w, "Failed to create client", http.StatusInternalServerError)
		return
	}

	// Return client registration response
	response := map[string]interface{}{
		"client_id":                  client.GetID(),
		"client_secret":              string(client.Secret),
		"redirect_uris":              client.GetRedirectURIs(),
		"grant_types":                client.GetGrantTypes(),
		"response_types":             client.GetResponseTypes(),
		"scope":                      strings.Join(client.GetScopes(), " "), // Convert array to space-separated string
		"token_endpoint_auth_method": "client_secret_basic",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ValidateTokenMiddleware creates middleware that validates OAuth tokens
func (s *OAuthServer) ValidateTokenMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract token from Authorization header
			_, ar, err := s.provider.IntrospectToken(ctx, fosite.AccessTokenFromRequest(r), fosite.AccessToken, &CustomSession{}, "")
			if err != nil {
				logf("Token validation error: %v", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Add user info to context if available
			if session, ok := ar.GetSession().(*CustomSession); ok && session.UserInfo != nil {
				ctx = context.WithValue(ctx, "user_info", session.UserInfo)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
