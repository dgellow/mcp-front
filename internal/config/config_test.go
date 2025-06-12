package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  string
		setupEnv    map[string]string
		wantErr     bool
		validate    func(*testing.T, *Config)
	}{
		{
			name: "valid config with env resolution",
			configJSON: `{
				"version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
				"proxy": {
					"baseURL": {"$env": "TEST_BASE_URL"},
					"addr": ":8080",
					"name": "test-proxy",
					"auth": {
						"kind": "bearerToken",
						"tokens": {
							"test": ["test-token"]
						}
					}
				},
				"mcpServers": {
					"test": {
						"url": "https://example.com",
						"env": {
							"API_KEY": {"$env": "TEST_API_KEY"}
						},
						"args": [{"$env": "TEST_ARG"}]
					}
				}
			}`,
			setupEnv: map[string]string{
				"TEST_BASE_URL": "https://test.example.com",
				"TEST_API_KEY":  "secret-key",
				"TEST_ARG":      "test-argument",
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Proxy.BaseURL.String() != "https://test.example.com" {
					t.Errorf("Expected baseURL to be resolved to https://test.example.com, got %s", cfg.Proxy.BaseURL.String())
				}
				if cfg.MCPServers["test"].Env["API_KEY"].String() != "secret-key" {
					t.Errorf("Expected API_KEY to be resolved to secret-key, got %s", cfg.MCPServers["test"].Env["API_KEY"].String())
				}
				if cfg.MCPServers["test"].Args[0].String() != "test-argument" {
					t.Errorf("Expected arg to be resolved to test-argument, got %s", cfg.MCPServers["test"].Args[0].String())
				}
			},
		},
		{
			name: "config with user token references preserved",
			configJSON: `{
				"version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
				"proxy": {
					"baseURL": "https://test.example.com",
					"addr": ":8080",
					"name": "test-proxy",
					"auth": {
						"kind": "oauth",
						"issuer": "https://test.example.com",
						"gcpProject": "test-project",
						"googleClientID": {"$env": "GOOGLE_CLIENT_ID"},
						"googleClientSecret": {"$env": "GOOGLE_CLIENT_SECRET"},
						"googleRedirectURI": "https://test.example.com/callback",
						"allowedDomains": ["example.com"],
						"tokenTTL": "1h",
						"storage": "memory",
						"jwtSecret": {"$env": "JWT_SECRET"},
						"encryptionKey": {"$env": "ENCRYPTION_KEY"}
					}
				},
				"mcpServers": {
					"notion": {
						"url": "https://notion-api.example.com",
						"requiresUserToken": true,
						"env": {
							"NOTION_TOKEN": {"$userToken": "{{token}}"}
						}
					}
				}
			}`,
			setupEnv: map[string]string{
				"GOOGLE_CLIENT_ID":     "test-client-id",
				"GOOGLE_CLIENT_SECRET": "test-client-secret",
				"JWT_SECRET":           strings.Repeat("a", 32),
				"ENCRYPTION_KEY":       strings.Repeat("b", 32),
			},
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				// Check that user token references are preserved
				envValue := cfg.MCPServers["notion"].Env["NOTION_TOKEN"]
				if !envValue.IsUserTokenRef() {
					t.Errorf("Expected NOTION_TOKEN to preserve user token reference")
				}
				
				// Test user token resolution - the template is "$userToken" so it should resolve to the token
				resolved := envValue.ResolveUserToken("test-user-token")
				if resolved != "test-user-token" {
					t.Errorf("Expected user token to resolve to test-user-token, got %s", resolved)
				}
				
				// Check that env refs were resolved
				oauthAuth := cfg.Proxy.Auth.(*OAuthAuthConfig)
				if oauthAuth.GoogleClientID.String() != "test-client-id" {
					t.Errorf("Expected GoogleClientID to be resolved, got %s", oauthAuth.GoogleClientID.String())
				}
			},
		},
		{
			name: "missing env var should fail",
			configJSON: `{
				"version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
				"proxy": {
					"baseURL": {"$env": "MISSING_ENV_VAR"},
					"addr": ":8080",
					"name": "test-proxy",
					"auth": {
						"kind": "bearerToken",
						"tokens": {
							"test": ["test-token"]
						}
					}
				},
				"mcpServers": {
					"test": {
						"url": "https://example.com"
					}
				}
			}`,
			setupEnv: map[string]string{},
			wantErr:  true,
		},
		{
			name: "invalid JSON should fail",
			configJSON: `{
				"version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
				"proxy": {
					"baseURL": "https://test.example.com"
					// missing comma
					"addr": ":8080"
				}
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment variables
			for k, v := range tt.setupEnv {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.json")
			
			err := os.WriteFile(configPath, []byte(tt.configJSON), 0644)
			if err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// Test Load function
			cfg, err := Load(configPath)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if cfg == nil {
				t.Errorf("Expected config but got nil")
				return
			}

			// Run custom validation if provided
			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestParseMCPClientConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *MCPClientConfig
		wantType string
		wantErr  bool
	}{
		{
			name: "stdio transport",
			config: &MCPClientConfig{
				TransportType: MCPClientTypeStdio,
				Command:       "python",
				Args:          ConfigValueSlice{NewConfigValue("script.py")},
			},
			wantType: "stdio",
			wantErr:  false,
		},
		{
			name: "sse transport",
			config: &MCPClientConfig{
				TransportType: MCPClientTypeSSE,
				URL:           "https://api.example.com",
			},
			wantType: "sse",
			wantErr:  false,
		},
		{
			name: "inferred stdio from command",
			config: &MCPClientConfig{
				Command: "python",
				Args:    ConfigValueSlice{NewConfigValue("script.py")},
			},
			wantType: "stdio",
			wantErr:  false,
		},
		{
			name: "inferred sse from url",
			config: &MCPClientConfig{
				URL: "https://api.example.com",
			},
			wantType: "sse",
			wantErr:  false,
		},
		{
			name: "missing both command and url",
			config: &MCPClientConfig{
				TransportType: MCPClientTypeStdio,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseMCPClientConfig(tt.config)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			// Check the type of returned result
			switch tt.wantType {
			case "stdio":
				if _, ok := result.(*StdioMCPClientConfig); !ok {
					t.Errorf("Expected *StdioMCPClientConfig, got %T", result)
				}
			case "sse":
				if _, ok := result.(*SSEMCPClientConfig); !ok {
					t.Errorf("Expected *SSEMCPClientConfig, got %T", result)
				}
			}
		})
	}
}

func TestValidateRawConfig(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantErr    bool
	}{
		{
			name: "valid config",
			configJSON: `{
				"version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
				"proxy": {
					"baseURL": "https://test.example.com",
					"addr": ":8080",
					"name": "test-proxy",
					"auth": {
						"kind": "bearerToken",
						"tokens": {
							"test": ["token1"]
						}
					}
				},
				"mcpServers": {
					"test": {
						"url": "https://example.com"
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "hardcoded oauth secret should fail",
			configJSON: `{
				"version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
				"proxy": {
					"baseURL": "https://test.example.com",
					"addr": ":8080",
					"name": "test-proxy",
					"auth": {
						"kind": "oauth",
						"issuer": "https://test.example.com",
						"gcpProject": "test-project",
						"googleClientId": "test-client-id",
						"googleClientSecret": "hardcoded-secret",
						"jwtSecret": "hardcoded-jwt-secret"
					}
				},
				"mcpServers": {
					"test": {
						"url": "https://example.com"
					}
				}
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rawConfig map[string]interface{}
			err := json.Unmarshal([]byte(tt.configJSON), &rawConfig)
			if err != nil {
				t.Fatalf("Failed to unmarshal test JSON: %v", err)
			}

			err = validateRawConfig(rawConfig)
			
			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}