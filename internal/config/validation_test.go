package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFile(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		wantErrors    []string
		wantWarnings  []string
		wantErrCount  int
		wantWarnCount int
	}{
		{
			name: "valid_service_auth_config",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio",
						"command": "docker",
						"serviceAuths": [{
							"type": "bearer",
							"tokens": ["token1"]
						}]
					}
				}
			}`,
			wantErrCount:  0,
			wantWarnCount: 0,
		},
		{
			name: "valid_oauth_config",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"googleClientId": {"$env": "CLIENT_ID"},
						"googleClientSecret": {"$env": "CLIENT_SECRET"},
						"googleRedirectUri": "https://example.com/callback",
						"jwtSecret": {"$env": "JWT_SECRET"},
						"encryptionKey": {"$env": "ENCRYPTION_KEY"},
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio",
						"command": "docker"
					}
				}
			}`,
			wantErrCount:  0,
			wantWarnCount: 0,
		},
		{
			name: "missing_version",
			config: `{
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {}
			}`,
			wantErrors:   []string{"version field is required"},
			wantErrCount: 1,
		},
		{
			name: "invalid_version",
			config: `{
				"version": "v2.0.0",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {}
			}`,
			wantErrors:   []string{"unsupported version: v2.0.0"},
			wantErrCount: 1,
		},
		{
			name: "missing_proxy",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"mcpServers": {}
			}`,
			wantErrors:   []string{"proxy field is required and must be an object"},
			wantErrCount: 1,
		},
		{
			name: "missing_proxy_fields",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {},
				"mcpServers": {}
			}`,
			wantErrors: []string{
				"baseURL is required",
				"addr is required",
			},
			wantErrCount: 2,
		},
		{
			name: "bash_style_env_vars",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "$BASE_URL",
					"addr": "${ADDR}"
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio",
						"command": "docker",
						"env": {
							"DB_URL": "${DATABASE_URL}"
						}
					}
				}
			}`,
			wantWarnings: []string{
				"found bash-style syntax '$BASE_URL'",
				"found bash-style syntax '${ADDR}'",
				"found bash-style syntax '${DATABASE_URL}'",
			},
			wantWarnCount: 3,
		},
		{
			name: "missing_transport_type",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"postgres": {
						"command": "docker"
					}
				}
			}`,
			wantErrors:   []string{"transportType is required"},
			wantErrCount: 1,
		},
		{
			name: "stdio_missing_command",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio"
					}
				}
			}`,
			wantErrors:   []string{"command is required for stdio transport"},
			wantErrCount: 1,
		},
		{
			name: "sse_missing_url",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"api": {
						"transportType": "sse"
					}
				}
			}`,
			wantErrors:   []string{"url is required for sse transport"},
			wantErrCount: 1,
		},
		{
			name: "user_token_without_oauth",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"notion": {
						"transportType": "stdio",
						"command": "docker",
						"requiresUserToken": true
					}
				}
			}`,
			wantErrors: []string{
				"server requires user token but OAuth is not configured. Hint: User tokens require OAuth authentication - set proxy.auth.kind to 'oauth'",
				"tokenSetup is required when requiresUserToken is true. Hint: Add tokenSetup with displayName and instructions for users to obtain their token",
			},
			wantErrCount: 2,
		},
		{
			name: "user_token_missing_setup",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"googleClientId": "id",
						"googleClientSecret": "secret",
						"googleRedirectUri": "https://example.com/callback",
						"jwtSecret": "secret",
						"encryptionKey": "key",
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"notion": {
						"transportType": "stdio",
						"command": "docker",
						"requiresUserToken": true
					}
				}
			}`,
			wantErrors:   []string{"tokenSetup is required when requiresUserToken is true. Hint: Add tokenSetup with displayName and instructions for users to obtain their token"},
			wantErrCount: 1,
		},
		{
			name: "oauth_missing_fields",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth"
					}
				},
				"mcpServers": {}
			}`,
			wantErrors: []string{
				"issuer is required for OAuth",
				"googleClientId is required for OAuth",
				"googleClientSecret is required for OAuth",
				"googleRedirectUri is required for OAuth",
				"jwtSecret is required for OAuth. Hint: Must be at least 32 bytes long for HMAC-SHA256",
				"encryptionKey is required for OAuth. Hint: Must be exactly 32 bytes for AES-256-GCM encryption",
				"at least one allowed domain is required for OAuth",
				"at least one allowed origin is required for OAuth (CORS configuration)",
			},
			wantErrCount: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.json")
			err := os.WriteFile(configPath, []byte(tt.config), 0644)
			require.NoError(t, err)

			// Validate
			result, err := ValidateFile(configPath)
			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Check error count
			assert.Equal(t, tt.wantErrCount, len(result.Errors),
				"expected %d errors but got %d: %v", tt.wantErrCount, len(result.Errors), result.Errors)

			// Check warning count
			assert.Equal(t, tt.wantWarnCount, len(result.Warnings),
				"expected %d warnings but got %d: %v", tt.wantWarnCount, len(result.Warnings), result.Warnings)

			// Check specific errors
			for _, wantErr := range tt.wantErrors {
				found := false
				for _, err := range result.Errors {
					if err.Message == wantErr {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error '%s' not found in %v", wantErr, result.Errors)
			}

			// Check specific warnings
			for _, wantWarn := range tt.wantWarnings {
				found := false
				for _, warn := range result.Warnings {
					if warn.Message != "" && contains(warn.Message, wantWarn) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected warning containing '%s' not found in %v", wantWarn, result.Warnings)
			}
		})
	}
}

func TestValidateFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	err := os.WriteFile(configPath, []byte(`{invalid json`), 0644)
	require.NoError(t, err)

	result, err := ValidateFile(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Errors))
	assert.Contains(t, result.Errors[0].Message, "invalid JSON")
}

func TestValidateFile_FileNotFound(t *testing.T) {
	result, err := ValidateFile("/nonexistent/file.json")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "reading config file")
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
