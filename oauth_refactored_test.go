package main

import (
	"testing"
	"time"
)

func TestOAuthRefactoredArchitecture(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL:           Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	server, err := NewOAuthServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	// Test storage layer (only stores/retrieves data)
	t.Run("storage_layer", func(t *testing.T) {
		// Test state generation
		state1 := server.storage.generateState()
		state2 := server.storage.generateState()
		if state1 == state2 {
			t.Error("Generated states should be unique")
		}
		if len(state1) == 0 {
			t.Error("Generated state should not be empty")
		}

		// Test client creation
		clientID := "test-client-123"
		redirectURIs := []string{"https://example.com/callback"}
		scopes := []string{"read", "write"}
		client := server.storage.createClient(clientID, redirectURIs, scopes, config.Issuer)

		if client.GetID() != clientID {
			t.Errorf("Expected client ID %s, got %s", clientID, client.GetID())
		}
		if len(client.GetScopes()) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(client.GetScopes()))
		}
	})

	// Test auth service (business logic)
	t.Run("auth_service", func(t *testing.T) {
		// Test scope parsing
		metadata := map[string]interface{}{
			"redirect_uris": []interface{}{"https://example.com/callback"},
			"scope":         "read write",
		}

		redirectURIs, scopes, err := server.authService.parseClientRequest(metadata)
		if err != nil {
			t.Fatalf("Failed to parse client request: %v", err)
		}

		if len(redirectURIs) != 1 {
			t.Errorf("Expected 1 redirect URI, got %d", len(redirectURIs))
		}
		if len(scopes) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(scopes))
		}
		if scopes[0] != "read" || scopes[1] != "write" {
			t.Errorf("Expected scopes [read, write], got %v", scopes)
		}
	})

	// Test domain validator
	t.Run("domain_validator", func(t *testing.T) {
		validator := newDomainValidator([]string{"example.com", "test.org"})

		// Valid domains
		if err := validator.validateDomain("example.com"); err != nil {
			t.Errorf("Expected example.com to be valid: %v", err)
		}
		if err := validator.validateDomain("TEST.ORG"); err != nil {
			t.Errorf("Expected TEST.ORG to be valid (case insensitive): %v", err)
		}

		// Invalid domains
		if err := validator.validateDomain("evil.com"); err == nil {
			t.Error("Expected evil.com to be invalid")
		}
		if err := validator.validateDomain(""); err == nil {
			t.Error("Expected empty domain to be invalid")
		}

		// No domains configured (should allow all)
		validatorNoRestriction := newDomainValidator([]string{})
		if err := validatorNoRestriction.validateDomain("anything.com"); err != nil {
			t.Errorf("Expected no domain restriction to allow all: %v", err)
		}
	})

	// Test separation of concerns
	t.Run("separation_of_concerns", func(t *testing.T) {
		// Storage should only do data operations
		if server.storage.MemoryStore == nil {
			t.Error("Storage should embed MemoryStore")
		}

		// Auth service should handle business logic
		if server.authService.config == nil {
			t.Error("Auth service should have config")
		}
		if server.authService.validator == nil {
			t.Error("Auth service should have validator")
		}

		// Server should coordinate between layers
		if server.provider == nil {
			t.Error("Server should have OAuth provider")
		}
		if server.storage == nil {
			t.Error("Server should have storage")
		}
		if server.authService == nil {
			t.Error("Server should have auth service")
		}
	})
}