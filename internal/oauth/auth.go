package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/dgellow/mcp-front/internal"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// authService handles Google OAuth integration and user validation
type authService struct {
	googleOAuth    *oauth2.Config
	allowedDomains []string
}

// UserInfo represents Google user information
type UserInfo struct {
	Email         string `json:"email"`
	HostedDomain  string `json:"hd"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	VerifiedEmail bool   `json:"verified_email"`
}

// newAuthService creates a new auth service instance
func newAuthService(config Config) (*authService, error) {
	// Use custom OAuth endpoints if provided (for testing)
	endpoint := google.Endpoint
	if authURL := os.Getenv("GOOGLE_OAUTH_AUTH_URL"); authURL != "" {
		endpoint.AuthURL = authURL
	}
	if tokenURL := os.Getenv("GOOGLE_OAUTH_TOKEN_URL"); tokenURL != "" {
		endpoint.TokenURL = tokenURL
	}

	googleConfig := &oauth2.Config{
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		RedirectURL:  config.GoogleRedirectURI,
		Scopes: []string{
			"openid",
			"email",
		},
		Endpoint: endpoint,
	}

	internal.Logf("Google OAuth config - ClientID: %s, RedirectURL: %s", config.GoogleClientID, config.GoogleRedirectURI)

	return &authService{
		googleOAuth:    googleConfig,
		allowedDomains: config.AllowedDomains,
	}, nil
}

// googleAuthURL returns the Google OAuth authorization URL
func (s *authService) googleAuthURL(state string) string {
	return s.googleOAuth.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
	)
}

// exchangeCodeForToken exchanges the authorization code for a token
func (s *authService) exchangeCodeForToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.googleOAuth.Exchange(ctx, code)
}

// validateUser validates the Google OAuth token and checks domain membership
func (s *authService) validateUser(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := s.googleOAuth.Client(ctx, token)
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	if customURL := os.Getenv("GOOGLE_USERINFO_URL"); customURL != "" {
		userInfoURL = customURL
	}
	resp, err := client.Get(userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Validate domain if configured
	if len(s.allowedDomains) > 0 {
		if userInfo.HostedDomain == "" {
			return nil, fmt.Errorf("user %s does not belong to a hosted domain", userInfo.Email)
		}

		domainAllowed := false
		for _, domain := range s.allowedDomains {
			if userInfo.HostedDomain == domain {
				domainAllowed = true
				break
			}
		}

		if !domainAllowed {
			return nil, fmt.Errorf("user %s domain %s is not in allowed domains", userInfo.Email, userInfo.HostedDomain)
		}
	}

	return &userInfo, nil
}

// parseClientRequest parses and validates a client registration request
func (s *authService) parseClientRequest(metadata map[string]interface{}) ([]string, []string, error) {
	// Extract redirect URIs
	redirectURIs := []string{}
	if uris, ok := metadata["redirect_uris"].([]interface{}); ok {
		for _, uri := range uris {
			if uriStr, ok := uri.(string); ok {
				redirectURIs = append(redirectURIs, uriStr)
			}
		}
	}

	if len(redirectURIs) == 0 {
		return nil, nil, fmt.Errorf("redirect_uris is required")
	}

	// Extract scopes
	scopes := []string{"read", "write"} // Default MCP scopes
	if clientScopes, ok := metadata["scope"].(string); ok {
		if strings.TrimSpace(clientScopes) != "" {
			scopes = strings.Fields(clientScopes)
		}
	}

	return redirectURIs, scopes, nil
}
