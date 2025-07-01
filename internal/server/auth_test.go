package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test authentication boundaries - focus only on auth layer
func TestAuthenticationBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		path        string
		expectAuth  bool
		description string
	}{
		{
			name: "oauth_endpoints_are_public",
			config: &config.Config{
				Proxy: config.ProxyConfig{
					BaseURL: "https://test.example.com",
					Auth: &config.OAuthAuthConfig{
						Kind:               config.AuthKindOAuth,
						GoogleClientID:     "test-client-id",
						GoogleClientSecret: "test-client-secret",
						GoogleRedirectURI:  "https://test.example.com/callback",
						JWTSecret:          strings.Repeat("a", 32),
						EncryptionKey:      strings.Repeat("b", 32),
						TokenTTL:           "1h",
						Storage:            "memory",
					},
				},
			},
			path:        "/.well-known/oauth-authorization-server",
			expectAuth:  false,
			description: "OAuth discovery must be public",
		},
		{
			name: "health_is_public",
			config: &config.Config{
				Proxy: config.ProxyConfig{
					BaseURL: "https://test.example.com",
					Auth: &config.OAuthAuthConfig{
						Kind:               config.AuthKindOAuth,
						GoogleClientID:     "test-client-id",
						GoogleClientSecret: "test-client-secret",
						GoogleRedirectURI:  "https://test.example.com/callback",
						JWTSecret:          strings.Repeat("a", 32),
						EncryptionKey:      strings.Repeat("b", 32),
						TokenTTL:           "1h",
						Storage:            "memory",
					},
				},
			},
			path:        "/health",
			expectAuth:  false,
			description: "Health check must be public",
		},
		{
			name: "token_management_requires_auth",
			config: &config.Config{
				Proxy: config.ProxyConfig{
					BaseURL: "https://test.example.com",
					Auth: &config.OAuthAuthConfig{
						Kind:               config.AuthKindOAuth,
						GoogleClientID:     "test-client-id",
						GoogleClientSecret: "test-client-secret",
						GoogleRedirectURI:  "https://test.example.com/callback",
						JWTSecret:          strings.Repeat("a", 32),
						EncryptionKey:      strings.Repeat("b", 32),
						TokenTTL:           "1h",
						Storage:            "memory",
					},
				},
			},
			path:        "/my/tokens",
			expectAuth:  true,
			description: "Token management requires auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(context.Background(), tt.config)
			require.NoError(t, err)

			srv := httptest.NewServer(server)
			defer srv.Close()

			// Test without session cookie
			req, err := http.NewRequest("GET", srv.URL+tt.path, nil)
			require.NoError(t, err)

			// Use a client that doesn't follow redirects to check auth behavior
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			if tt.expectAuth {
				// Browser SSO redirects to OAuth when no session cookie
				assert.Equal(t, http.StatusFound, resp.StatusCode, tt.description+" - should redirect to OAuth")
				location := resp.Header.Get("Location")
				assert.Contains(t, location, "auth", tt.description+" - should redirect to Google OAuth")
			} else {
				// Should not be blocked by auth
				assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode, tt.description+" - should not require auth")
				assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, tt.description+" - should not require auth")
				assert.NotEqual(t, http.StatusFound, resp.StatusCode, tt.description+" - should not redirect for auth")
			}

			// Test with valid session cookie (if auth is expected)
			if tt.expectAuth {
				// Create a valid session cookie using the encryptor
				if oauthConfig, ok := tt.config.Proxy.Auth.(*config.OAuthAuthConfig); ok {
					// Create session data
					sessionData := oauth.SessionData{
						Email:   "test@example.com",
						Expires: time.Now().Add(24 * time.Hour),
					}
					jsonData, err := json.Marshal(sessionData)
					require.NoError(t, err)

					// Encrypt the session data
					encryptor, err := crypto.NewEncryptor([]byte(oauthConfig.EncryptionKey))
					require.NoError(t, err)
					encrypted, err := encryptor.Encrypt(string(jsonData))
					require.NoError(t, err)

					// Test with valid session cookie
					req2, err := http.NewRequest("GET", srv.URL+tt.path, nil)
					require.NoError(t, err)
					req2.AddCookie(&http.Cookie{
						Name:  "mcp_session",
						Value: encrypted,
					})

					resp2, err := client.Do(req2)
					require.NoError(t, err)
					defer resp2.Body.Close()

					// Should allow access with valid session
					assert.Equal(t, http.StatusOK, resp2.StatusCode, tt.description+" - should allow with valid session")
				}
			}
		})
	}
}

// Test that MCP endpoints respect auth configuration
func TestMCPAuthConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		expectAuth  bool
		description string
	}{
		{
			name: "mcp_without_oauth_is_public",
			config: &config.Config{
				Proxy: config.ProxyConfig{
					BaseURL: "https://test.example.com",
				},
				MCPServers: map[string]*config.MCPClientConfig{
					"test": {URL: "https://test.example.com"},
				},
			},
			expectAuth:  false,
			description: "MCP endpoints without OAuth config should be public",
		},
		{
			name: "mcp_with_oauth_requires_auth",
			config: &config.Config{
				Proxy: config.ProxyConfig{
					BaseURL: "https://test.example.com",
					Auth: &config.OAuthAuthConfig{
						Kind:               config.AuthKindOAuth,
						GoogleClientID:     "test-client-id",
						GoogleClientSecret: "test-client-secret",
						GoogleRedirectURI:  "https://test.example.com/callback",
						JWTSecret:          strings.Repeat("a", 32),
						EncryptionKey:      strings.Repeat("b", 32),
						TokenTTL:           "1h",
						Storage:            "memory",
					},
				},
				MCPServers: map[string]*config.MCPClientConfig{
					"test": {URL: "https://test.example.com"},
				},
			},
			expectAuth:  true,
			description: "MCP endpoints with OAuth config should require auth",
		},
		{
			name: "mcp_with_service_auth_requires_auth",
			config: &config.Config{
				Proxy: config.ProxyConfig{
					BaseURL: "https://test.example.com",
				},
				MCPServers: map[string]*config.MCPClientConfig{
					"test": {
						URL: "https://test.example.com",
						ServiceAuths: []config.ServiceAuth{
							{
								Type:   config.ServiceAuthTypeBearer,
								Tokens: []string{"test-token"},
							},
						},
					},
				},
			},
			expectAuth:  true,
			description: "MCP endpoints with service auth should require auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(context.Background(), tt.config)
			require.NoError(t, err)

			srv := httptest.NewServer(server)
			defer srv.Close()

			// Test the MCP endpoint
			req, err := http.NewRequest("GET", srv.URL+"/test/sse", nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			if tt.expectAuth {
				// Should be blocked by auth middleware - not reach MCP layer
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, tt.description)
			} else {
				// Should pass auth and reach MCP layer (where it might fail with 500 due to network)
				// The key is it should NOT be 401/403 (auth rejection)
				assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode, tt.description)
				assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, tt.description)
			}
		})
	}
}

// Test bearer token authentication specifically
func TestBearerTokenAuth(t *testing.T) {
	config := &config.Config{
		Proxy: config.ProxyConfig{
			BaseURL: "https://test.example.com",
		},
		MCPServers: map[string]*config.MCPClientConfig{
			"test": {
				URL: "https://test.example.com",
				ServiceAuths: []config.ServiceAuth{
					{
						Type:   config.ServiceAuthTypeBearer,
						Tokens: []string{"valid-token", "another-valid-token"},
					},
				},
			},
		},
	}

	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)

	srv := httptest.NewServer(server)
	defer srv.Close()

	tests := []struct {
		name       string
		authHeader string
		expectPass bool
	}{
		{
			name:       "no_auth_header",
			authHeader: "",
			expectPass: false,
		},
		{
			name:       "invalid_token",
			authHeader: "Bearer invalid-token",
			expectPass: false,
		},
		{
			name:       "valid_token_1",
			authHeader: "Bearer valid-token",
			expectPass: true,
		},
		{
			name:       "valid_token_2",
			authHeader: "Bearer another-valid-token",
			expectPass: true,
		},
		{
			name:       "wrong_auth_scheme",
			authHeader: "Basic dGVzdA==",
			expectPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", srv.URL+"/test/sse", nil)
			require.NoError(t, err)

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			if tt.expectPass {
				// Should pass auth (might fail at MCP layer with 500, but not 401/403)
				assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode, "Valid auth should pass")
				assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, "Valid auth should pass")
			} else {
				// Should be blocked by auth
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Invalid auth should be blocked")
			}
		})
	}
}
