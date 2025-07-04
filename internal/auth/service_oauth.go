package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
	"golang.org/x/oauth2"
)

// ServiceOAuthClient handles OAuth flows for external MCP services
type ServiceOAuthClient struct {
	storage    storage.UserTokenStore
	baseURL    string
	httpClient *http.Client
	stateCache map[string]*ServiceOAuthState // In production, use distributed cache
}

// ServiceOAuthState stores OAuth flow state for external service authentication (mcp-front → external service)
type ServiceOAuthState struct {
	Service   string
	UserEmail string
	CreatedAt time.Time
}

// NewServiceOAuthClient creates a new OAuth client for external services
func NewServiceOAuthClient(storage storage.UserTokenStore, baseURL string) *ServiceOAuthClient {
	return &ServiceOAuthClient{
		storage:    storage,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		stateCache: make(map[string]*ServiceOAuthState),
	}
}

// StartOAuthFlow initiates OAuth flow for a service
func (c *ServiceOAuthClient) StartOAuthFlow(
	ctx context.Context,
	userEmail string,
	serviceName string,
	serviceConfig *config.MCPClientConfig,
) (string, error) {
	if serviceConfig.UserAuthentication == nil ||
		serviceConfig.UserAuthentication.Type != config.UserAuthTypeOAuth {
		return "", fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	auth := serviceConfig.UserAuthentication

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     string(auth.ClientID),
		ClientSecret: string(auth.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.AuthorizationURL,
			TokenURL: auth.TokenURL,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName),
		Scopes:      auth.Scopes,
	}

	// Generate state parameter
	state := crypto.GenerateSecureToken()
	c.stateCache[state] = &ServiceOAuthState{
		Service:   serviceName,
		UserEmail: userEmail,
		CreatedAt: time.Now(),
	}

	// Clean up old states (older than 10 minutes)
	c.cleanupOldStates()

	// Generate authorization URL
	authURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	log.LogInfoWithFields("service_oauth", "Starting OAuth flow", map[string]any{
		"service":  serviceName,
		"user":     userEmail,
		"authURL":  authURL,
		"redirect": oauth2Config.RedirectURL,
	})

	return authURL, nil
}

// HandleCallback processes OAuth callback
func (c *ServiceOAuthClient) HandleCallback(
	ctx context.Context,
	serviceName string,
	code string,
	state string,
	serviceConfig *config.MCPClientConfig,
) (userEmail string, err error) {
	// Validate state
	oauthState, exists := c.stateCache[state]
	if !exists {
		return "", fmt.Errorf("invalid state parameter")
	}
	delete(c.stateCache, state) // One-time use

	// Validate service matches
	if oauthState.Service != serviceName {
		return "", fmt.Errorf("service mismatch in OAuth callback")
	}

	auth := serviceConfig.UserAuthentication
	if auth == nil || auth.Type != config.UserAuthTypeOAuth {
		return "", fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     string(auth.ClientID),
		ClientSecret: string(auth.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.AuthorizationURL,
			TokenURL: auth.TokenURL,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName),
		Scopes:      auth.Scopes,
	}

	// Exchange code for token
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to exchange code for token", map[string]any{
			"service": serviceName,
			"error":   err.Error(),
		})
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}

	// Store the token
	storedToken := &storage.StoredToken{
		Type: storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    token.Expiry,
			TokenType:    token.TokenType,
			Scopes:       auth.Scopes,
		},
		UpdatedAt: time.Now(),
	}

	if err := c.storage.SetUserToken(ctx, oauthState.UserEmail, serviceName, storedToken); err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to store OAuth token", map[string]any{
			"service": serviceName,
			"user":    oauthState.UserEmail,
			"error":   err.Error(),
		})
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	log.LogInfoWithFields("service_oauth", "OAuth flow completed successfully", map[string]any{
		"service": serviceName,
		"user":    oauthState.UserEmail,
	})

	return oauthState.UserEmail, nil
}

// RefreshToken refreshes an OAuth token if needed
func (c *ServiceOAuthClient) RefreshToken(
	ctx context.Context,
	userEmail string,
	serviceName string,
	serviceConfig *config.MCPClientConfig,
) error {
	// Get current token
	storedToken, err := c.storage.GetUserToken(ctx, userEmail, serviceName)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if storedToken.Type != storage.TokenTypeOAuth || storedToken.OAuthData == nil {
		return fmt.Errorf("token is not an OAuth token")
	}

	// Check if refresh is needed (refresh if expires within 5 minutes)
	if time.Until(storedToken.OAuthData.ExpiresAt) > 5*time.Minute {
		return nil // Token still valid
	}

	if storedToken.OAuthData.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	auth := serviceConfig.UserAuthentication
	if auth == nil || auth.Type != config.UserAuthTypeOAuth {
		return fmt.Errorf("service configuration missing OAuth settings")
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     string(auth.ClientID),
		ClientSecret: string(auth.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.AuthorizationURL,
			TokenURL: auth.TokenURL,
		},
		Scopes: auth.Scopes,
	}

	// Create token source for refresh
	oldToken := &oauth2.Token{
		AccessToken:  storedToken.OAuthData.AccessToken,
		RefreshToken: storedToken.OAuthData.RefreshToken,
		Expiry:       storedToken.OAuthData.ExpiresAt,
		TokenType:    storedToken.OAuthData.TokenType,
	}

	tokenSource := oauth2Config.TokenSource(ctx, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to refresh token", map[string]any{
			"service": serviceName,
			"user":    userEmail,
			"error":   err.Error(),
		})
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update stored token
	storedToken.OAuthData.AccessToken = newToken.AccessToken
	if newToken.RefreshToken != "" {
		storedToken.OAuthData.RefreshToken = newToken.RefreshToken
	}
	storedToken.OAuthData.ExpiresAt = newToken.Expiry
	storedToken.UpdatedAt = time.Now()

	if err := c.storage.SetUserToken(ctx, userEmail, serviceName, storedToken); err != nil {
		return fmt.Errorf("failed to store refreshed token: %w", err)
	}

	log.LogInfoWithFields("service_oauth", "Token refreshed successfully", map[string]any{
		"service": serviceName,
		"user":    userEmail,
		"expiry":  newToken.Expiry,
	})

	return nil
}

// GetConnectURL generates the OAuth connect URL for a service
func (c *ServiceOAuthClient) GetConnectURL(serviceName string, returnPath string) string {
	params := url.Values{}
	params.Set("service", serviceName)
	if returnPath != "" {
		params.Set("return", returnPath)
	}
	return fmt.Sprintf("%s/oauth/connect?%s", c.baseURL, params.Encode())
}

// cleanupOldStates removes expired state entries
func (c *ServiceOAuthClient) cleanupOldStates() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for state, oauthState := range c.stateCache {
		if oauthState.CreatedAt.Before(cutoff) {
			delete(c.stateCache, state)
		}
	}
}

// ParseTokenResponse parses a token response for custom OAuth implementations
func ParseTokenResponse(body []byte) (*oauth2.Token, error) {
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	token := &oauth2.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		TokenType:    resp.TokenType,
	}

	if resp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}

	if resp.Scope != "" {
		token = token.WithExtra(map[string]any{
			"scope": strings.Split(resp.Scope, " "),
		})
	}

	return token, nil
}
