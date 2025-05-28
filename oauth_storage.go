package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleoauth2 "google.golang.org/api/oauth2/v2"
)

// GCPIAMStorage implements fosite.Storage with GCP IAM integration
type GCPIAMStorage struct {
	*storage.MemoryStore
	config         *OAuthConfig
	googleOAuth    *oauth2.Config
	stateCache     *sync.Map // map[string]*fosite.AuthorizeRequest
	oauth2Service  *googleoauth2.Service
}

// NewGCPIAMStorage creates a new storage instance with GCP IAM validation
func NewGCPIAMStorage(config *OAuthConfig) (*GCPIAMStorage, error) {
	// Initialize Google OAuth config
	googleConfig := &oauth2.Config{
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		RedirectURL:  config.GoogleRedirectURI,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// Initialize Google OAuth2 service
	oauth2Service, err := googleoauth2.NewService(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 service: %w", err)
	}

	return &GCPIAMStorage{
		MemoryStore:   storage.NewMemoryStore(),
		config:        config,
		googleOAuth:   googleConfig,
		stateCache:    &sync.Map{},
		oauth2Service: oauth2Service,
	}, nil
}

// UserInfo represents Google user information
type UserInfo struct {
	Email         string `json:"email"`
	HostedDomain  string `json:"hd"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	VerifiedEmail bool   `json:"verified_email"`
}

// ValidateGoogleToken validates a Google OAuth token and checks domain membership
func (s *GCPIAMStorage) ValidateGoogleToken(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	// Get user info from Google
	userInfoService := s.oauth2Service.Userinfo
	userInfo, err := userInfoService.Get().Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Convert to our UserInfo struct
	verifiedEmail := false
	if userInfo.VerifiedEmail != nil {
		verifiedEmail = *userInfo.VerifiedEmail
	}
	
	user := &UserInfo{
		Email:         userInfo.Email,
		HostedDomain:  userInfo.Hd,
		Name:          userInfo.Name,
		Picture:       userInfo.Picture,
		VerifiedEmail: verifiedEmail,
	}

	// Validate domain if configured
	if len(s.config.AllowedDomains) > 0 {
		if user.HostedDomain == "" {
			return nil, fmt.Errorf("user %s does not belong to a hosted domain", user.Email)
		}

		domainAllowed := false
		for _, domain := range s.config.AllowedDomains {
			if user.HostedDomain == domain {
				domainAllowed = true
				break
			}
		}

		if !domainAllowed {
			return nil, fmt.Errorf("user %s domain %s is not in allowed domains", user.Email, user.HostedDomain)
		}
	}

	return user, nil
}

// GenerateState creates a cryptographically secure state parameter
func (s *GCPIAMStorage) GenerateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// StoreAuthorizeRequest stores an authorize request with state
func (s *GCPIAMStorage) StoreAuthorizeRequest(state string, req fosite.AuthorizeRequester) {
	s.stateCache.Store(state, req)
}

// GetAuthorizeRequest retrieves an authorize request by state
func (s *GCPIAMStorage) GetAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool) {
	if req, ok := s.stateCache.Load(state); ok {
		s.stateCache.Delete(state) // One-time use
		return req.(fosite.AuthorizeRequester), true
	}
	return nil, false
}

// CreateClient creates a dynamic client for MCP
func (s *GCPIAMStorage) CreateClient(ctx context.Context, clientMetadata map[string]interface{}) (*fosite.DefaultClient, error) {
	clientID := s.GenerateState() // Reuse secure random generation
	
	// Extract client metadata
	redirectURIs := []string{}
	if uris, ok := clientMetadata["redirect_uris"].([]interface{}); ok {
		for _, uri := range uris {
			if uriStr, ok := uri.(string); ok {
				redirectURIs = append(redirectURIs, uriStr)
			}
		}
	}

	scopes := []string{"read", "write"} // Default MCP scopes
	if clientScopes, ok := clientMetadata["scope"].(string); ok {
		scopes = []string{clientScopes}
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte(s.GenerateState()), // Generate secure secret
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{s.config.Issuer},
	}

	// Store the client in memory store
	s.MemoryStore.Clients[clientID] = client
	
	return client, nil
}

// CustomSession extends DefaultSession with user information
type CustomSession struct {
	*fosite.DefaultSession
	UserInfo *UserInfo `json:"user_info,omitempty"`
}

// Clone implements fosite.Session
func (s *CustomSession) Clone() fosite.Session {
	return &CustomSession{
		DefaultSession: s.DefaultSession.Clone().(*fosite.DefaultSession),
		UserInfo:       s.UserInfo,
	}
}

// NewCustomSession creates a new session with user info
func NewCustomSession(userInfo *UserInfo) *CustomSession {
	return &CustomSession{
		DefaultSession: &fosite.DefaultSession{
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().Add(time.Hour),
				fosite.RefreshToken: time.Now().Add(24 * time.Hour),
			},
			Username: userInfo.Email,
			Subject:  userInfo.Email,
		},
		UserInfo: userInfo,
	}
}