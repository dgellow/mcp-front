package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleoauth2 "google.golang.org/api/oauth2/v2"
)

// authService handles OAuth business logic
type authService struct {
	config        *OAuthConfig
	googleOAuth   *oauth2.Config
	oauth2Service *googleoauth2.Service
	validator     *domainValidator
}

// newAuthService creates a new auth service
func newAuthService(config *OAuthConfig) (*authService, error) {
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

	oauth2Service, err := googleoauth2.NewService(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create OAuth2 service: %w", err)
	}

	return &authService{
		config:        config,
		googleOAuth:   googleConfig,
		oauth2Service: oauth2Service,
		validator:     newDomainValidator(config.AllowedDomains),
	}, nil
}

// googleAuthURL returns the URL for Google OAuth
func (s *authService) googleAuthURL(state string) string {
	return s.googleOAuth.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
	)
}

// exchangeCodeForToken exchanges authorization code for token
func (s *authService) exchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.googleOAuth.Exchange(ctx, code)
}

// validateUser validates a Google token and returns user info
func (s *authService) validateUser(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := s.googleOAuth.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var googleUser struct {
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
		HD            string `json:"hd"` // Hosted domain
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	userInfo := &UserInfo{
		Email:        googleUser.Email,
		Name:         googleUser.Name,
		HostedDomain: googleUser.HD,
	}

	// Validate domain
	if err := s.validator.validateDomain(userInfo.HostedDomain); err != nil {
		return nil, err
	}

	return userInfo, nil
}

// parseClientRequest parses client registration metadata
func (s *authService) parseClientRequest(metadata map[string]interface{}) (redirectURIs []string, scopes []string, err error) {
	// Parse redirect URIs
	if uris, ok := metadata["redirect_uris"].([]interface{}); ok {
		for _, uri := range uris {
			if uriStr, ok := uri.(string); ok {
				redirectURIs = append(redirectURIs, uriStr)
			}
		}
	}

	// Parse scopes - default to "read write"
	scopes = []string{"read", "write"}
	if clientScopes, ok := metadata["scope"].(string); ok {
		if strings.TrimSpace(clientScopes) != "" {
			scopes = strings.Fields(clientScopes)
		}
	}

	if len(redirectURIs) == 0 {
		return nil, nil, fmt.Errorf("redirect_uris required")
	}

	return redirectURIs, scopes, nil
}