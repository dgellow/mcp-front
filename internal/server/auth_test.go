package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dgellow/mcp-front/internal/config"
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

			// Test without auth header
			req, err := http.NewRequest("GET", srv.URL+tt.path, nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			if tt.expectAuth {
				// Should be blocked by auth middleware
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, tt.description+" - should require auth")
			} else {
				// Should not be blocked by auth
				assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode, tt.description+" - should not require auth")
				assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, tt.description+" - should not require auth")
			}

			// Test with invalid auth header (if auth is expected)
			if tt.expectAuth {
				req2, err := http.NewRequest("GET", srv.URL+tt.path, nil)
				require.NoError(t, err)
				req2.Header.Set("Authorization", "Bearer invalid-token")

				resp2, err := http.DefaultClient.Do(req2)
				require.NoError(t, err)
				defer resp2.Body.Close()

				assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, tt.description+" - should reject invalid tokens")
			}
		})
	}
}

// Test that MCP endpoints respect auth configuration
func TestMCPAuthConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		config         *config.Config
		expectAuth     bool
		description    string
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
			name: "mcp_with_bearer_auth_requires_auth",
			config: &config.Config{
				Proxy: config.ProxyConfig{
					BaseURL: "https://test.example.com",
				},
				MCPServers: map[string]*config.MCPClientConfig{
					"test": {
						URL: "https://test.example.com",
						Options: &config.Options{
							AuthTokens: []string{"test-token"},
						},
					},
				},
			},
			expectAuth:  true,
			description: "MCP endpoints with bearer tokens should require auth",
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
				Options: &config.Options{
					AuthTokens: []string{"valid-token", "another-valid-token"},
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