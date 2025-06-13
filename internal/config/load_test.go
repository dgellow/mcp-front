package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateConfig_UserTokensRequireOAuth(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError string
	}{
		{
			name: "user_tokens_without_oauth",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"notion": {
						TransportType:     MCPClientTypeSSE,
						URL:               "https://notion.example.com",
						RequiresUserToken: true,
						TokenSetup: &TokenSetupConfig{
							DisplayName: "Notion",
						},
					},
				},
			},
			expectError: "server notion requires user tokens but OAuth is not configured",
		},
		{
			name: "user_tokens_with_bearer_auth",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &BearerTokenAuthConfig{
						Kind: AuthKindBearerToken,
						Tokens: map[string][]string{
							"notion": {"token123"},
						},
					},
				},
				MCPServers: map[string]*MCPClientConfig{
					"notion": {
						TransportType:     MCPClientTypeSSE,
						URL:               "https://notion.example.com",
						RequiresUserToken: true,
						TokenSetup: &TokenSetupConfig{
							DisplayName: "Notion",
						},
					},
				},
			},
			expectError: "server notion requires user tokens but OAuth is not configured",
		},
		{
			name: "user_tokens_with_oauth",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &OAuthAuthConfig{
						Kind:               AuthKindOAuth,
						Issuer:             "https://test.example.com",
						GoogleClientID:     "client-id",
						GoogleClientSecret: "secret",
						GoogleRedirectURI:  "https://test.example.com/callback",
						JWTSecret:          "12345678901234567890123456789012",
						AllowedDomains:     []string{"example.com"},
						Storage:            "memory",
					},
				},
				MCPServers: map[string]*MCPClientConfig{
					"notion": {
						TransportType:     MCPClientTypeSSE,
						URL:               "https://notion.example.com",
						RequiresUserToken: true,
						TokenSetup: &TokenSetupConfig{
							DisplayName: "Notion",
						},
					},
				},
			},
			expectError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}