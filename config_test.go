package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestLoadBearerTokenConfig(t *testing.T) {
	config, err := load("config-token.example.json")
	if err != nil {
		t.Fatalf("Failed to load bearer token config: %v", err)
	}

	if config.Proxy.Name != "mcp-front-dev" {
		t.Errorf("Expected name mcp-front-dev, got %s", config.Proxy.Name)
	}

	// Check that bearer tokens were distributed to servers
	postgresTokens := config.MCPServers["postgres"].Options.AuthTokens
	if len(postgresTokens) != 2 {
		t.Errorf("Expected 2 postgres tokens, got %d", len(postgresTokens))
	}
	if postgresTokens[0] != "dev-token-postgres-1" {
		t.Errorf("Expected first postgres token to be dev-token-postgres-1, got %s", postgresTokens[0])
	}

	// Verify OAuth is not configured for bearer token mode
	if _, ok := config.Proxy.Auth.(*OAuthAuthConfig); ok {
		t.Error("Should not have OAuth config for bearer token auth")
	}
}

func TestEnvRefResolution(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		envVars  map[string]string
		expected interface{}
		wantErr  bool
	}{
		{
			name: "simple env ref with value",
			input: map[string]interface{}{
				"$env": "TEST_VAR",
			},
			envVars: map[string]string{
				"TEST_VAR": "test-value",
			},
			expected: "test-value",
		},
		{
			name: "env ref with default",
			input: map[string]interface{}{
				"$env":    "MISSING_VAR",
				"default": "default-value",
			},
			envVars:  map[string]string{},
			expected: "default-value",
		},
		{
			name: "missing env without default",
			input: map[string]interface{}{
				"$env": "MISSING_VAR",
			},
			envVars: map[string]string{},
			wantErr: true,
		},
		{
			name: "nested env refs",
			input: map[string]interface{}{
				"auth": map[string]interface{}{
					"secret": map[string]interface{}{
						"$env": "SECRET",
					},
				},
			},
			envVars: map[string]string{
				"SECRET": "secret-value",
			},
			expected: map[string]interface{}{
				"auth": map[string]interface{}{
					"secret": "secret-value",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			result, err := resolveEnvRef(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveEnvRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Check if we have maps to compare
				if resultMap, ok := result.(map[string]interface{}); ok {
					if expectedMap, ok := tt.expected.(map[string]interface{}); ok {
						// Simple string representation comparison for this test
						if fmt.Sprintf("%v", resultMap) != fmt.Sprintf("%v", expectedMap) {
							t.Errorf("Expected %v, got %v", expectedMap, resultMap)
						}
					} else {
						t.Errorf("Expected %v, got %v", tt.expected, result)
					}
				} else if result != tt.expected {
					t.Errorf("Expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}

func TestConfigVersionValidation(t *testing.T) {
	// Create a temporary config with wrong version
	tmpFile := "/tmp/test-wrong-version.json"
	content := `{
		"version": "v1.0.0",
		"proxy": {
			"baseURL": "http://localhost:8080",
			"addr": ":8080",
			"name": "test",
			"auth": {
				"kind": "bearerToken",
				"tokens": {"test": ["token1"]}
			}
		},
		"mcpServers": {
			"test": {
				"command": "echo",
				"args": ["hello"]
			}
		}
	}`

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	defer os.Remove(tmpFile)

	_, err := load(tmpFile)
	if err == nil {
		t.Error("Expected error for unsupported version")
	}
	if !strings.Contains(err.Error(), "unsupported config version") {
		t.Errorf("Expected unsupported version error, got: %v", err)
	}
}