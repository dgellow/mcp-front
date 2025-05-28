package main

import (
	"os"
	"testing"
	"time"
)

func TestOAuthConfigParsing(t *testing.T) {
	configJSON := `{
		"mcpProxy": {
			"baseURL": "https://test.example.com",
			"addr": ":8080",
			"name": "Test Proxy",
			"version": "1.0.0"
		},
		"oauth": {
			"issuer": "https://test.example.com",
			"gcp_project": "test-project",
			"allowed_domains": ["example.com", "test.com"],
			"token_ttl": "1h",
			"storage": "memory",
			"google_client_id": "test-client-id",
			"google_client_secret": "test-client-secret",
			"google_redirect_uri": "https://test.example.com/callback"
		},
		"mcpServers": {
			"test": {
				"command": "echo",
				"args": ["hello"]
			}
		}
	}`

	// Create temporary config file
	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(configJSON)); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load and test config
	config, err := load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test MCP Proxy config
	if config.McpProxy.BaseURL != "https://test.example.com" {
		t.Errorf("Expected baseURL 'https://test.example.com', got '%s'", config.McpProxy.BaseURL)
	}

	// Test OAuth config
	if config.OAuth == nil {
		t.Fatal("OAuth config should not be nil")
	}

	if config.OAuth.Issuer != "https://test.example.com" {
		t.Errorf("Expected issuer 'https://test.example.com', got '%s'", config.OAuth.Issuer)
	}

	if config.OAuth.GCPProject != "test-project" {
		t.Errorf("Expected GCP project 'test-project', got '%s'", config.OAuth.GCPProject)
	}

	expectedDomains := []string{"example.com", "test.com"}
	if len(config.OAuth.AllowedDomains) != len(expectedDomains) {
		t.Errorf("Expected %d allowed domains, got %d", len(expectedDomains), len(config.OAuth.AllowedDomains))
	}

	for i, domain := range expectedDomains {
		if config.OAuth.AllowedDomains[i] != domain {
			t.Errorf("Expected domain '%s' at index %d, got '%s'", domain, i, config.OAuth.AllowedDomains[i])
		}
	}

	if config.OAuth.TokenTTL.ToDuration() != time.Hour {
		t.Errorf("Expected token TTL 1h, got %v", config.OAuth.TokenTTL)
	}

	if config.OAuth.GoogleClientID != "test-client-id" {
		t.Errorf("Expected Google client ID 'test-client-id', got '%s'", config.OAuth.GoogleClientID)
	}

	// Test MCP servers
	if len(config.McpServers) != 1 {
		t.Errorf("Expected 1 MCP server, got %d", len(config.McpServers))
	}

	testServer, exists := config.McpServers["test"]
	if !exists {
		t.Error("Expected 'test' server to exist")
	}

	if testServer.Command != "echo" {
		t.Errorf("Expected command 'echo', got '%s'", testServer.Command)
	}
}

func TestConfigWithoutOAuth(t *testing.T) {
	configJSON := `{
		"mcpProxy": {
			"baseURL": "https://test.example.com",
			"addr": ":8080",
			"name": "Test Proxy",
			"version": "1.0.0"
		},
		"mcpServers": {
			"test": {
				"command": "echo",
				"args": ["hello"]
			}
		}
	}`

	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(configJSON)); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	config, err := load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// OAuth config should be nil when not specified
	if config.OAuth != nil {
		t.Error("OAuth config should be nil when not specified")
	}
}

func TestMCPClientConfigV2Parsing(t *testing.T) {
	tests := []struct {
		name     string
		config   *MCPClientConfigV2
		expected interface{}
		hasError bool
	}{
		{
			name: "stdio config",
			config: &MCPClientConfigV2{
				Command: "echo",
				Args:    []string{"hello"},
				Env:     map[string]string{"TEST": "value"},
			},
			expected: &StdioMCPClientConfig{
				Command: "echo",
				Args:    []string{"hello"},
				Env:     map[string]string{"TEST": "value"},
			},
			hasError: false,
		},
		{
			name: "SSE config",
			config: &MCPClientConfigV2{
				URL:     "https://example.com/sse",
				Headers: map[string]string{"Authorization": "Bearer token"},
			},
			expected: &SSEMCPClientConfig{
				URL:     "https://example.com/sse",
				Headers: map[string]string{"Authorization": "Bearer token"},
			},
			hasError: false,
		},
		{
			name: "streamable config",
			config: &MCPClientConfigV2{
				TransportType: MCPClientTypeStreamable,
				URL:           "https://example.com/stream",
				Headers:       map[string]string{"Authorization": "Bearer token"},
				Timeout:       30 * time.Second,
			},
			expected: &StreamableMCPClientConfig{
				URL:     "https://example.com/stream",
				Headers: map[string]string{"Authorization": "Bearer token"},
				Timeout: 30 * time.Second,
			},
			hasError: false,
		},
		{
			name: "invalid config",
			config: &MCPClientConfigV2{
				// No command, URL, or transport type
			},
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseMCPClientConfigV2(tt.config)

			if tt.hasError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Compare results based on type
			switch expected := tt.expected.(type) {
			case *StdioMCPClientConfig:
				stdio, ok := result.(*StdioMCPClientConfig)
				if !ok {
					t.Errorf("Expected StdioMCPClientConfig, got %T", result)
					return
				}
				if stdio.Command != expected.Command {
					t.Errorf("Expected command '%s', got '%s'", expected.Command, stdio.Command)
				}
			case *SSEMCPClientConfig:
				sse, ok := result.(*SSEMCPClientConfig)
				if !ok {
					t.Errorf("Expected SSEMCPClientConfig, got %T", result)
					return
				}
				if sse.URL != expected.URL {
					t.Errorf("Expected URL '%s', got '%s'", expected.URL, sse.URL)
				}
			case *StreamableMCPClientConfig:
				streamable, ok := result.(*StreamableMCPClientConfig)
				if !ok {
					t.Errorf("Expected StreamableMCPClientConfig, got %T", result)
					return
				}
				if streamable.URL != expected.URL {
					t.Errorf("Expected URL '%s', got '%s'", expected.URL, streamable.URL)
				}
			}
		})
	}
}