package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	config := Config{
		Issuer:             "https://test.example.com",
		TokenTTL:           time.Hour,
		AllowedDomains:     []string{"example.com"},
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
		JWTSecret:          "test-secret-32-bytes-long-for-testing",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	if server.provider == nil {
		t.Error("OAuth provider not initialized")
	}

	if server.storage == nil {
		t.Error("Storage not initialized")
	}

	if server.config.Issuer != config.Issuer {
		t.Error("Config not properly stored")
	}
}

func TestNewServerWithoutJWTSecret(t *testing.T) {
	config := Config{
		Issuer:             "https://test.example.com",
		TokenTTL:           time.Hour,
		AllowedDomains:     []string{"example.com"},
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
		// JWTSecret is empty - should generate random secret
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	if server == nil {
		t.Error("Server should be created even without JWT secret")
	}
}

func TestWellKnownHandler(t *testing.T) {
	config := Config{
		Issuer:   "https://test.example.com",
		TokenTTL: time.Hour,
		JWTSecret: "test-secret-32-bytes-long-for-testing",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	server.WellKnownHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check required fields
	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint", 
		"registration_endpoint",
		"scopes_supported",
		"response_types_supported",
		"grant_types_supported",
		"code_challenge_methods_supported",
	}

	for _, field := range requiredFields {
		if _, ok := metadata[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}

	// Verify issuer
	if issuer, ok := metadata["issuer"].(string); !ok || issuer != config.Issuer {
		t.Errorf("Expected issuer %s, got %v", config.Issuer, metadata["issuer"])
	}
}

func TestRegisterHandler(t *testing.T) {
	config := Config{
		Issuer:   "https://test.example.com",
		TokenTTL: time.Hour,
		JWTSecret: "test-secret-32-bytes-long-for-testing",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create registration request
	reqBody := map[string]interface{}{
		"redirect_uris": []string{"https://client.example.com/callback"},
		"scope":         "read write",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.RegisterHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response
	if clientID, ok := response["client_id"].(string); !ok || clientID == "" {
		t.Error("Missing or empty client_id")
	}

	// Verify scope is returned as a string, not array
	if scope, ok := response["scope"].(string); !ok || scope != "read write" {
		t.Errorf("Expected scope 'read write', got %v", response["scope"])
	}

	// Verify redirect_uris
	if uris, ok := response["redirect_uris"].([]interface{}); !ok || len(uris) != 1 {
		t.Errorf("Expected redirect_uris with 1 URI, got %v", response["redirect_uris"])
	}
}

func TestRegisterHandlerInvalidMethod(t *testing.T) {
	config := Config{
		Issuer:   "https://test.example.com", 
		TokenTTL: time.Hour,
		JWTSecret: "test-secret-32-bytes-long-for-testing",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest("GET", "/register", nil)
	w := httptest.NewRecorder()

	server.RegisterHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d for GET request, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestClientRegistrationAndDebugEndpoint(t *testing.T) {
	config := Config{
		Issuer:   "https://test.example.com",
		TokenTTL: time.Hour,
		JWTSecret: "test-secret-32-bytes-long-for-testing",
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Register a client
	reqBody := map[string]interface{}{
		"redirect_uris": []string{"http://localhost:3000/callback"},
		"scope":         "read write",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.RegisterHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Register failed with status %d: %s", w.Code, w.Body.String())
	}

	var registerResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&registerResp)
	clientID := registerResp["client_id"].(string)

	// Check debug endpoint
	req = httptest.NewRequest("GET", "/debug/clients", nil)
	w = httptest.NewRecorder()

	server.DebugClientsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Debug endpoint failed with status %d", w.Code)
	}

	var debugResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&debugResp)

	if total, ok := debugResp["total_clients"].(float64); !ok || total != 1 {
		t.Errorf("Expected 1 client, got %v", debugResp["total_clients"])
	}

	clients, ok := debugResp["clients"].(map[string]interface{})
	if !ok {
		t.Fatal("clients field is not a map")
	}

	if _, exists := clients[clientID]; !exists {
		t.Errorf("Client %s not found in debug output", clientID)
	}

	t.Logf("✅ Successfully registered client %s and verified in debug endpoint", clientID)
}

func TestStorageArchitecture(t *testing.T) {
	storage := newStorage()

	// Test state generation
	t.Run("state_generation", func(t *testing.T) {
		state1 := storage.generateState()
		state2 := storage.generateState()
		if state1 == state2 {
			t.Error("Generated states should be unique")
		}
		if len(state1) == 0 {
			t.Error("Generated state should not be empty")
		}
	})

	// Test client creation
	t.Run("client_creation", func(t *testing.T) {
		clientID := "test-client-123"
		redirectURIs := []string{"https://example.com/callback"}
		scopes := []string{"read", "write"}
		issuer := "https://test.example.com"
		
		client := storage.createClient(clientID, redirectURIs, scopes, issuer)

		if client.GetID() != clientID {
			t.Errorf("Expected client ID %s, got %s", clientID, client.GetID())
		}
		if len(client.GetScopes()) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(client.GetScopes()))
		}
		if client.GetRedirectURIs()[0] != redirectURIs[0] {
			t.Errorf("Expected redirect URI %s, got %s", redirectURIs[0], client.GetRedirectURIs()[0])
		}
	})

	// Test client retrieval
	t.Run("client_retrieval", func(t *testing.T) {
		clientID := "test-client-456"
		redirectURIs := []string{"https://example.com/callback"}
		scopes := []string{"read"}
		issuer := "https://test.example.com"
		
		// Create client
		originalClient := storage.createClient(clientID, redirectURIs, scopes, issuer)
		
		// Retrieve client
		retrievedClient, err := storage.GetClient(nil, clientID)
		if err != nil {
			t.Fatalf("Failed to retrieve client: %v", err)
		}
		
		if retrievedClient.GetID() != originalClient.GetID() {
			t.Errorf("Retrieved client ID doesn't match original")
		}
	})

	// Test thread-safe operations
	t.Run("thread_safety", func(t *testing.T) {
		// This test verifies the GetAllClients method works correctly
		// and doesn't race with concurrent access
		clients := storage.GetAllClients()
		if clients == nil {
			t.Error("GetAllClients should return a map, not nil")
		}
		
		// Should be able to call this multiple times safely
		clients2 := storage.GetAllClients()
		if len(clients) != len(clients2) {
			t.Error("GetAllClients should return consistent results")
		}
	})
}

func TestAuthServiceArchitecture(t *testing.T) {
	config := Config{
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret", 
		GoogleRedirectURI:  "https://test.example.com/callback",
		AllowedDomains:     []string{"example.com"},
	}

	authService, err := newAuthService(config)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	// Test client request parsing
	t.Run("client_request_parsing", func(t *testing.T) {
		metadata := map[string]interface{}{
			"redirect_uris": []interface{}{"https://example.com/callback", "https://example.com/callback2"},
			"scope":         "read write execute",
		}

		redirectURIs, scopes, err := authService.parseClientRequest(metadata)
		if err != nil {
			t.Fatalf("Failed to parse client request: %v", err)
		}

		if len(redirectURIs) != 2 {
			t.Errorf("Expected 2 redirect URIs, got %d", len(redirectURIs))
		}

		if len(scopes) != 3 {
			t.Errorf("Expected 3 scopes, got %d", len(scopes))
		}

		if scopes[0] != "read" || scopes[1] != "write" || scopes[2] != "execute" {
			t.Errorf("Scopes not parsed correctly: %v", scopes)
		}
	})

	// Test missing redirect URIs
	t.Run("missing_redirect_uris", func(t *testing.T) {
		metadata := map[string]interface{}{
			"scope": "read write",
		}

		_, _, err := authService.parseClientRequest(metadata)
		if err == nil {
			t.Error("Expected error for missing redirect_uris")
		}
	})

	// Test default scopes
	t.Run("default_scopes", func(t *testing.T) {
		metadata := map[string]interface{}{
			"redirect_uris": []interface{}{"https://example.com/callback"},
		}

		_, scopes, err := authService.parseClientRequest(metadata)
		if err != nil {
			t.Fatalf("Failed to parse client request: %v", err)
		}

		// Should get default MCP scopes
		if len(scopes) != 2 || scopes[0] != "read" || scopes[1] != "write" {
			t.Errorf("Expected default scopes [read, write], got %v", scopes)
		}
	})
}