package main

import (
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
		errorMsg  string
	}{
		{
			name: "valid complete config",
			config: &Config{
				McpProxy: &MCPProxyConfigV2{
					BaseURL: "https://example.com",
					Addr:    ":8080",
					Name:    "Test Proxy",
					Version: "1.0.0",
				},
				OAuth: &OAuthConfig{
					Issuer:             "https://example.com",
					GCPProject:         "test-project",
					AllowedDomains:     []string{"example.com"},
					TokenTTL: Duration(time.Hour),
					Storage:            "memory",
					GoogleClientID:     "test-client-id",
					GoogleClientSecret: "test-secret",
					GoogleRedirectURI:  "https://example.com/callback",
				},
				McpServers: map[string]*MCPClientConfigV2{
					"test": {
						Command: "echo",
						Args:    []string{"hello"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "missing mcpProxy",
			config: &Config{
				McpServers: map[string]*MCPClientConfigV2{
					"test": {Command: "echo"},
				},
			},
			expectErr: true,
			errorMsg:  "mcpProxy",
		},
		{
			name: "invalid baseURL",
			config: &Config{
				McpProxy: &MCPProxyConfigV2{
					BaseURL: "://invalid-url",
					Addr:    ":8080",
					Name:    "Test",
					Version: "1.0.0",
				},
				McpServers: map[string]*MCPClientConfigV2{
					"test": {Command: "echo"},
				},
			},
			expectErr: true,
			errorMsg:  "baseURL",
		},
		{
			name: "invalid OAuth issuer",
			config: &Config{
				McpProxy: &MCPProxyConfigV2{
					BaseURL: "https://example.com",
					Addr:    ":8080",
					Name:    "Test",
					Version: "1.0.0",
				},
				OAuth: &OAuthConfig{
					Issuer:         "not-a-url",
					GCPProject:     "test",
					AllowedDomains: []string{"example.com"},
					TokenTTL: Duration(time.Hour),
				},
				McpServers: map[string]*MCPClientConfigV2{
					"test": {Command: "echo"},
				},
			},
			expectErr: true,
			errorMsg:  "issuer",
		},
		{
			name: "empty allowed domains",
			config: &Config{
				McpProxy: &MCPProxyConfigV2{
					BaseURL: "https://example.com",
					Addr:    ":8080",
					Name:    "Test",
					Version: "1.0.0",
				},
				OAuth: &OAuthConfig{
					Issuer:             "https://example.com",
					GCPProject:         "test",
					AllowedDomains:     []string{},
					TokenTTL: Duration(time.Hour),
					GoogleClientID:     "test",
					GoogleClientSecret: "test",
					GoogleRedirectURI:  "https://example.com/callback",
				},
				McpServers: map[string]*MCPClientConfigV2{
					"test": {Command: "echo"},
				},
			},
			expectErr: true,
			errorMsg:  "allowed_domains",
		},
		{
			name: "invalid server config - both command and URL",
			config: &Config{
				McpProxy: &MCPProxyConfigV2{
					BaseURL: "https://example.com",
					Addr:    ":8080",
					Name:    "Test",
					Version: "1.0.0",
				},
				McpServers: map[string]*MCPClientConfigV2{
					"test": {
						Command: "echo",
						URL:     "https://example.com",
					},
				},
			},
			expectErr: true,
			errorMsg:  "cannot specify both",
		},
		{
			name: "invalid server config - neither command nor URL",
			config: &Config{
				McpProxy: &MCPProxyConfigV2{
					BaseURL: "https://example.com",
					Addr:    ":8080",
					Name:    "Test",
					Version: "1.0.0",
				},
				McpServers: map[string]*MCPClientConfigV2{
					"test": {},
				},
			},
			expectErr: true,
			errorMsg:  "either 'command'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			
			if tt.expectErr {
				if err == nil {
					t.Error("Expected validation error but got none")
				} else if tt.errorMsg != "" && !containsSubstring(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected validation error: %v", err)
				}
			}
		})
	}
}

func TestSanitizeConfig(t *testing.T) {
	config := &Config{
		McpProxy: &MCPProxyConfigV2{
			BaseURL: "  https://example.com/  ",
			Addr:    "  :8080  ",
			Name:    "  Test Proxy  ",
			Version: "  1.0.0  ",
		},
		OAuth: &OAuthConfig{
			Issuer:             "  https://example.com/  ",
			GCPProject:         "  test-project  ",
			AllowedDomains:     []string{"  Example.COM  ", "  TEST.com  "},
			GoogleClientID:     "  test-client-id  ",
			GoogleClientSecret: "  test-secret  ",
			GoogleRedirectURI:  "  https://example.com/callback  ",
		},
		McpServers: map[string]*MCPClientConfigV2{
			"test": {
				Command: "  echo  ",
				URL:     "  https://example.com  ",
				Args:    []string{"  hello  ", "  world  "},
			},
		},
	}

	SanitizeConfig(config)

	// Check trimming
	if config.McpProxy.BaseURL != "https://example.com" {
		t.Errorf("Expected baseURL 'https://example.com', got '%s'", config.McpProxy.BaseURL)
	}

	if config.McpProxy.Addr != ":8080" {
		t.Errorf("Expected addr ':8080', got '%s'", config.McpProxy.Addr)
	}

	if config.OAuth.Issuer != "https://example.com" {
		t.Errorf("Expected issuer 'https://example.com', got '%s'", config.OAuth.Issuer)
	}

	// Check domain normalization (lowercase)
	expectedDomains := []string{"example.com", "test.com"}
	for i, expected := range expectedDomains {
		if config.OAuth.AllowedDomains[i] != expected {
			t.Errorf("Expected domain '%s' at index %d, got '%s'", expected, i, config.OAuth.AllowedDomains[i])
		}
	}

	// Check server config trimming
	testServer := config.McpServers["test"]
	if testServer.Command != "echo" {
		t.Errorf("Expected command 'echo', got '%s'", testServer.Command)
	}

	if testServer.Args[0] != "hello" || testServer.Args[1] != "world" {
		t.Errorf("Expected args ['hello', 'world'], got %v", testServer.Args)
	}
}

func TestValidationErrors(t *testing.T) {
	// Test single validation error
	err := ValidationError{Field: "test", Message: "test error"}
	expected := "validation error for field 'test': test error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}

	// Test multiple validation errors
	errors := ValidationErrors{
		{Field: "field1", Message: "error1"},
		{Field: "field2", Message: "error2"},
	}
	errorStr := errors.Error()
	if !containsSubstring(errorStr, "field1") || !containsSubstring(errorStr, "field2") {
		t.Errorf("Error string should contain both field names: %s", errorStr)
	}

	// Test empty validation errors
	emptyErrors := ValidationErrors{}
	if emptyErrors.Error() != "no validation errors" {
		t.Errorf("Expected 'no validation errors', got '%s'", emptyErrors.Error())
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				func() bool {
					for i := 1; i < len(s)-len(substr)+1; i++ {
						if s[i:i+len(substr)] == substr {
							return true
						}
					}
					return false
				}())))
}