package config

import (
	"testing"
)

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	validBearerTokenConfig := Config{
		Version: "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
		Proxy: ProxyConfig{
			BaseURL: "http://localhost:8080",
			Addr:    ":8080",
			Name:    "test-proxy",
			Auth: &BearerTokenAuthConfig{
				Kind: "bearerToken",
				Tokens: map[string][]string{
					"test": {"token1", "token2"},
				},
			},
		},
		MCPServers: map[string]*MCPClientConfig{
			"test": {
				Command: "echo",
				Args:    []string{"hello"},
			},
		},
	}

	validOAuthConfig := Config{
		Version: "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
		Proxy: ProxyConfig{
			BaseURL: "https://example.com",
			Addr:    ":8080",
			Name:    "oauth-proxy",
			Auth: &OAuthAuthConfig{
				Kind:               "oauth",
				Issuer:             "https://example.com",
				GCPProject:         "test-project",
				AllowedDomains:     []string{"example.com"},
				TokenTTL:           "1h",
				Storage:            "memory",
				GoogleClientID:     "test-client-id",
				GoogleClientSecret: map[string]interface{}{"$env": "GOOGLE_CLIENT_SECRET"},
				GoogleRedirectURI:  "https://example.com/callback",
				JWTSecret:          map[string]interface{}{"$env": "JWT_SECRET"},
			},
		},
		MCPServers: map[string]*MCPClientConfig{
			"test": {
				Command: "echo",
				Args:    []string{"hello"},
			},
		},
	}

	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid_bearer_token_config",
			config:  validBearerTokenConfig,
			wantErr: false,
		},
		{
			name:    "valid_oauth_config",
			config:  validOAuthConfig,
			wantErr: false,
		},
		{
			name: "missing_version",
			config: Config{
				Proxy:      validBearerTokenConfig.Proxy,
				MCPServers: validBearerTokenConfig.MCPServers,
			},
			wantErr: true,
			errMsg:  "version is required",
		},
		{
			name: "invalid_version",
			config: func() Config {
				c := validBearerTokenConfig
				c.Version = "v2.0.0"
				return c
			}(),
			wantErr: true,
			errMsg:  "unsupported version",
		},
		{
			name: "missing_proxy_base_url",
			config: func() Config {
				c := validBearerTokenConfig
				c.Proxy.BaseURL = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "baseURL is required",
		},
		{
			name: "invalid_proxy_base_url",
			config: func() Config {
				c := validBearerTokenConfig
				c.Proxy.BaseURL = "://invalid-url"
				return c
			}(),
			wantErr: true,
			errMsg:  "invalid URL",
		},
		{
			name: "missing_proxy_addr",
			config: func() Config {
				c := validBearerTokenConfig
				c.Proxy.Addr = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "address is required",
		},
		{
			name: "invalid_proxy_addr",
			config: func() Config {
				c := validBearerTokenConfig
				c.Proxy.Addr = "8080"
				return c
			}(),
			wantErr: true,
			errMsg:  "address must start with ':'",
		},
		{
			name: "missing_proxy_name",
			config: func() Config {
				c := validBearerTokenConfig
				c.Proxy.Name = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "missing_auth_config",
			config: func() Config {
				c := validBearerTokenConfig
				c.Proxy.Auth = nil
				return c
			}(),
			wantErr: true,
			errMsg:  "auth configuration is required",
		},
		{
			name: "empty_mcp_servers",
			config: func() Config {
				c := validBearerTokenConfig
				c.MCPServers = map[string]*MCPClientConfig{}
				return c
			}(),
			wantErr: true,
			errMsg:  "at least one MCP server is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			
			err := ValidateConfig(&tt.config)
			
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateBearerTokenAuth(t *testing.T) {
	t.Parallel()

	servers := map[string]*MCPClientConfig{
		"postgres": {Command: "postgres"},
		"notion":   {Command: "notion"},
	}

	tests := []struct {
		name    string
		auth    *BearerTokenAuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_bearer_token_auth",
			auth: &BearerTokenAuthConfig{
				Kind: "bearerToken",
				Tokens: map[string][]string{
					"postgres": {"token1", "token2"},
					"notion":   {"token3"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid_kind",
			auth: &BearerTokenAuthConfig{
				Kind: "invalid",
				Tokens: map[string][]string{
					"postgres": {"token1"},
				},
			},
			wantErr: true,
			errMsg:  "must be 'bearerToken'",
		},
		{
			name: "empty_tokens",
			auth: &BearerTokenAuthConfig{
				Kind:   "bearerToken",
				Tokens: map[string][]string{},
			},
			wantErr: true,
			errMsg:  "at least one token mapping is required",
		},
		{
			name: "server_not_found",
			auth: &BearerTokenAuthConfig{
				Kind: "bearerToken",
				Tokens: map[string][]string{
					"nonexistent": {"token1"},
				},
			},
			wantErr: true,
			errMsg:  "server 'nonexistent' not found in mcpServers",
		},
		{
			name: "empty_token_list",
			auth: &BearerTokenAuthConfig{
				Kind: "bearerToken",
				Tokens: map[string][]string{
					"postgres": {},
				},
			},
			wantErr: true,
			errMsg:  "at least one token is required",
		},
		{
			name: "empty_token_value",
			auth: &BearerTokenAuthConfig{
				Kind: "bearerToken",
				Tokens: map[string][]string{
					"postgres": {"valid-token", ""},
				},
			},
			wantErr: true,
			errMsg:  "token cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			
			err := validateBearerTokenAuth(tt.auth, servers)
			
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateOAuthAuth(t *testing.T) {
	t.Parallel()

	validOAuth := &OAuthAuthConfig{
		Kind:               "oauth",
		Issuer:             "https://example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL:           "1h",
		Storage:            "memory",
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: map[string]interface{}{"$env": "SECRET"},
		GoogleRedirectURI:  "https://example.com/callback",
		JWTSecret:          map[string]interface{}{"$env": "JWT_SECRET"},
	}

	tests := []struct {
		name    string
		auth    *OAuthAuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid_oauth_auth",
			auth:    validOAuth,
			wantErr: false,
		},
		{
			name: "invalid_kind",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.Kind = "invalid"
				return &a
			}(),
			wantErr: true,
			errMsg:  "must be 'oauth'",
		},
		{
			name: "missing_issuer",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.Issuer = ""
				return &a
			}(),
			wantErr: true,
			errMsg:  "issuer is required",
		},
		{
			name: "invalid_issuer_url",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.Issuer = "://invalid"
				return &a
			}(),
			wantErr: true,
			errMsg:  "invalid issuer URL",
		},
		{
			name: "http_issuer_non_localhost",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.Issuer = "http://example.com"
				return &a
			}(),
			wantErr: true,
			errMsg:  "issuer must use HTTPS in production",
		},
		{
			name: "http_issuer_localhost_allowed",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.Issuer = "http://localhost:8080"
				return &a
			}(),
			wantErr: false,
		},
		{
			name: "missing_gcp_project",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.GCPProject = ""
				return &a
			}(),
			wantErr: true,
			errMsg:  "GCP project ID is required",
		},
		{
			name: "empty_allowed_domains",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.AllowedDomains = []string{}
				return &a
			}(),
			wantErr: true,
			errMsg:  "at least one allowed domain is required",
		},
		{
			name: "invalid_domain_with_protocol",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.AllowedDomains = []string{"https://example.com"}
				return &a
			}(),
			wantErr: true,
			errMsg:  "domain should not contain protocol or path",
		},
		{
			name: "invalid_token_ttl",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.TokenTTL = "invalid"
				return &a
			}(),
			wantErr: true,
			errMsg:  "invalid duration",
		},
		{
			name: "token_ttl_too_short",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.TokenTTL = "1m"
				return &a
			}(),
			wantErr: true,
			errMsg:  "token TTL should be at least 5 minutes",
		},
		{
			name: "token_ttl_too_long",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.TokenTTL = "48h"
				return &a
			}(),
			wantErr: true,
			errMsg:  "token TTL should not exceed 24 hours",
		},
		{
			name: "invalid_storage",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.Storage = "invalid"
				return &a
			}(),
			wantErr: true,
			errMsg:  "storage must be 'memory' or 'redis'",
		},
		{
			name: "invalid_redirect_uri",
			auth: func() *OAuthAuthConfig {
				a := *validOAuth
				a.GoogleRedirectURI = "://invalid"
				return &a
			}(),
			wantErr: true,
			errMsg:  "invalid redirect URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			
			err := validateOAuthAuth(tt.auth)
			
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateMCPServersConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		servers map[string]*MCPClientConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_stdio_server",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					Args:    []string{"hello"},
					Env:     map[string]string{"KEY": "value"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid_http_server",
			servers: map[string]*MCPClientConfig{
				"test": {
					URL: "https://example.com/mcp",
				},
			},
			wantErr: false,
		},
		{
			name:    "empty_servers",
			servers: map[string]*MCPClientConfig{},
			wantErr: true,
			errMsg:  "at least one MCP server is required",
		},
		{
			name: "server_name_with_slash",
			servers: map[string]*MCPClientConfig{
				"test/server": {Command: "echo"},
			},
			wantErr: true,
			errMsg:  "server name cannot contain '/' or spaces",
		},
		{
			name: "server_name_with_space",
			servers: map[string]*MCPClientConfig{
				"test server": {Command: "echo"},
			},
			wantErr: true,
			errMsg:  "server name cannot contain '/' or spaces",
		},
		{
			name: "server_missing_command_and_url",
			servers: map[string]*MCPClientConfig{
				"test": {},
			},
			wantErr: true,
			errMsg:  "either 'command' (for stdio) or 'url' (for HTTP) is required",
		},
		{
			name: "server_both_command_and_url",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					URL:     "https://example.com",
				},
			},
			wantErr: true,
			errMsg:  "cannot specify both 'command' and 'url'",
		},
		{
			name: "invalid_server_url",
			servers: map[string]*MCPClientConfig{
				"test": {
					URL: "://invalid",
				},
			},
			wantErr: true,
			errMsg:  "invalid URL",
		},
		{
			name: "empty_env_key",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					Env:     map[string]string{"": "value"},
				},
			},
			wantErr: true,
			errMsg:  "environment variable key cannot be empty",
		},
		{
			name: "empty_env_value",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					Env:     map[string]string{"KEY": ""},
				},
			},
			wantErr: true,
			errMsg:  "environment variable value cannot be empty",
		},
		{
			name: "empty_auth_token",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					Options: &Options{
						AuthTokens: []string{"valid-token", ""},
					},
				},
			},
			wantErr: true,
			errMsg:  "auth token cannot be empty",
		},
		{
			name: "invalid_tool_filter_mode",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					Options: &Options{
						ToolFilter: &ToolFilterConfig{
							Mode: "invalid",
							List: []string{"tool1"},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "tool filter mode must be 'allow' or 'block'",
		},
		{
			name: "empty_tool_filter_list",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					Options: &Options{
						ToolFilter: &ToolFilterConfig{
							Mode: ToolFilterModeAllow,
							List: []string{},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "tool filter list cannot be empty when mode is specified",
		},
		{
			name: "empty_tool_name_in_filter",
			servers: map[string]*MCPClientConfig{
				"test": {
					Command: "echo",
					Options: &Options{
						ToolFilter: &ToolFilterConfig{
							Mode: ToolFilterModeAllow,
							List: []string{"tool1", ""},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "tool name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			
			err := validateMCPServersConfig(tt.servers)
			
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	t.Parallel()

	err := ValidationError{
		Field:   "test.field",
		Message: "test message",
	}

	expected := "validation error for field 'test.field': test message"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		errors   ValidationErrors
		expected string
	}{
		{
			name:     "empty_errors",
			errors:   ValidationErrors{},
			expected: "no validation errors",
		},
		{
			name: "single_error",
			errors: ValidationErrors{
				{Field: "field1", Message: "error1"},
			},
			expected: "validation error for field 'field1': error1",
		},
		{
			name: "multiple_errors",
			errors: ValidationErrors{
				{Field: "field1", Message: "error1"},
				{Field: "field2", Message: "error2"},
			},
			expected: "validation error for field 'field1': error1; validation error for field 'field2': error2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			
			result := tt.errors.Error()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// Test helper functions

func TestBearerTokenDistribution(t *testing.T) {
	t.Parallel()

	config := Config{
		Version: "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
		Proxy: ProxyConfig{
			BaseURL: "http://localhost:8080",
			Addr:    ":8080",
			Name:    "test-proxy",
			Auth: &BearerTokenAuthConfig{
				Kind: "bearerToken",
				Tokens: map[string][]string{
					"postgres": {"pg-token-1", "pg-token-2"},
					"notion":   {"notion-token-1"},
				},
			},
		},
		MCPServers: map[string]*MCPClientConfig{
			"postgres": {
				Command: "docker",
				Args:    []string{"run", "postgres-mcp"},
			},
			"notion": {
				Command: "docker", 
				Args:    []string{"run", "notion-mcp"},
			},
		},
	}

	// Manually trigger the token distribution that happens in load()
	if auth, ok := config.Proxy.Auth.(*BearerTokenAuthConfig); ok {
		for serverName, tokens := range auth.Tokens {
			if server, ok := config.MCPServers[serverName]; ok {
				if server.Options == nil {
					server.Options = &Options{}
				}
				server.Options.AuthTokens = tokens
			}
		}
	}

	err := ValidateConfig(&config)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Verify tokens were distributed correctly
	pgTokens := config.MCPServers["postgres"].Options.AuthTokens
	if len(pgTokens) != 2 {
		t.Errorf("expected 2 postgres tokens, got %d", len(pgTokens))
	}
	if pgTokens[0] != "pg-token-1" || pgTokens[1] != "pg-token-2" {
		t.Errorf("postgres tokens not distributed correctly: %v", pgTokens)
	}

	notionTokens := config.MCPServers["notion"].Options.AuthTokens
	if len(notionTokens) != 1 {
		t.Errorf("expected 1 notion token, got %d", len(notionTokens))
	}
	if notionTokens[0] != "notion-token-1" {
		t.Errorf("notion token not distributed correctly: %v", notionTokens)
	}
}


// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}