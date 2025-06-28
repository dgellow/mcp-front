package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgellow/mcp-front/internal/storage"
)

func TestProtectedResourceMetadataHandler(t *testing.T) {
	// Create a test server
	config := Config{
		Issuer:        "https://example.com",
		ProxyName:     "test-proxy",
		EncryptionKey: "test-encryption-key-32-bytes----", // Exactly 32 bytes for AES-256
		JWTSecret:     "test-jwt-secret-at-least-32-bytes-long",
	}
	
	store := storage.NewMemoryStorage()
	server, err := NewServer(config, store)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	// Create test request
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	// Call the handler
	server.ProtectedResourceMetadataHandler(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", w.Code, http.StatusOK)
	}

	// Parse response
	var metadata map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check required fields
	if resource, ok := metadata["resource"].(string); !ok || resource != "https://example.com" {
		t.Errorf("resource = %v, want %v", metadata["resource"], "https://example.com")
	}

	if authServers, ok := metadata["authorization_servers"].([]interface{}); !ok || len(authServers) != 1 {
		t.Errorf("authorization_servers = %v, want array with 1 element", metadata["authorization_servers"])
	} else if authServers[0] != "https://example.com" {
		t.Errorf("authorization_servers[0] = %v, want %v", authServers[0], "https://example.com")
	}

	// Check _links
	if links, ok := metadata["_links"].(map[string]interface{}); !ok {
		t.Error("_links field missing or not an object")
	} else {
		if authServerLink, ok := links["oauth-authorization-server"].(map[string]interface{}); !ok {
			t.Error("oauth-authorization-server link missing")
		} else {
			if href, ok := authServerLink["href"].(string); !ok || href != "https://example.com/.well-known/oauth-authorization-server" {
				t.Errorf("oauth-authorization-server href = %v, want %v", href, "https://example.com/.well-known/oauth-authorization-server")
			}
		}
	}
}