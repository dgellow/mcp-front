package config

import (
	"testing"
	"time"

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
						EncryptionKey:      "test-encryption-key-32-bytes-ok!",
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

func TestValidateConfig_SessionConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		expectError   string
		expectTimeout time.Duration
		expectCleanup time.Duration
	}{
		{
			name: "valid_session_config",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &BearerTokenAuthConfig{
						Kind: AuthKindBearerToken,
					},
					Sessions: &SessionConfig{
						Timeout:         10 * time.Minute,
						CleanupInterval: 2 * time.Minute,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError:   "",
			expectTimeout: 10 * time.Minute,
			expectCleanup: 2 * time.Minute,
		},
		{
			name: "negative_timeout",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &BearerTokenAuthConfig{
						Kind: AuthKindBearerToken,
					},
					Sessions: &SessionConfig{
						Timeout:         -1 * time.Minute,
						CleanupInterval: 2 * time.Minute,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError: "proxy.sessions.timeout cannot be negative",
		},
		{
			name: "negative_cleanup_interval",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &BearerTokenAuthConfig{
						Kind: AuthKindBearerToken,
					},
					Sessions: &SessionConfig{
						Timeout:         10 * time.Minute,
						CleanupInterval: -30 * time.Second,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError: "proxy.sessions.cleanupInterval cannot be negative",
		},
		{
			name: "empty_session_config",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &BearerTokenAuthConfig{
						Kind: AuthKindBearerToken,
					},
					Sessions: &SessionConfig{
						Timeout:         0,
						CleanupInterval: 0,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError:   "",
			expectTimeout: 0,
			expectCleanup: 0,
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
				if tt.config.Proxy.Sessions != nil {
					assert.Equal(t, tt.expectTimeout, tt.config.Proxy.Sessions.Timeout)
					assert.Equal(t, tt.expectCleanup, tt.config.Proxy.Sessions.CleanupInterval)
				}
			}
		})
	}
}
