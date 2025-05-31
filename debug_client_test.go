package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRegistrationAndDebugEndpoint(t *testing.T) {
	// Create OAuth config
	config := &OAuthConfig{
		Issuer:         "http://localhost:8080",
		TokenTTL:       Duration(3600 * 1000000000), // 1 hour in nanoseconds
		AllowedDomains: []string{"example.com"},
		GCPProject:     "test-project",
	}

	// Create OAuth server
	server, err := NewOAuthServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	// Test client registration
	registrationBody := `{
		"redirect_uris": ["http://localhost:3000/callback"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"scope": "read write"
	}`

	req := httptest.NewRequest("POST", "/register", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.RegisterHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	// Parse the registration response to get client ID
	var regResponse map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &regResponse); err != nil {
		t.Fatalf("Failed to parse registration response: %v", err)
	}

	clientID, ok := regResponse["client_id"].(string)
	if !ok {
		t.Fatalf("No client_id in registration response")
	}

	// Now test the debug endpoint
	debugReq := httptest.NewRequest("GET", "/debug/clients", nil)
	debugW := httptest.NewRecorder()

	server.DebugClientsHandler(debugW, debugReq)

	if debugW.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for debug endpoint, got %d: %s", debugW.Code, debugW.Body.String())
	}

	// Parse the debug response
	var debugResponse map[string]interface{}
	if err := json.Unmarshal(debugW.Body.Bytes(), &debugResponse); err != nil {
		t.Fatalf("Failed to parse debug response: %v", err)
	}

	// Check that we have 1 client
	totalClients, ok := debugResponse["total_clients"].(float64)
	if !ok {
		t.Fatalf("No total_clients in debug response")
	}

	if int(totalClients) != 1 {
		t.Errorf("Expected 1 client in debug response, got %d", int(totalClients))
	}

	// Check that our client is in the response
	clients, ok := debugResponse["clients"].(map[string]interface{})
	if !ok {
		t.Fatalf("No clients in debug response")
	}

	if _, exists := clients[clientID]; !exists {
		t.Errorf("Client %s not found in debug response", clientID)
	}

	t.Logf("✅ Successfully registered client %s and verified in debug endpoint", clientID)
	t.Logf("Debug response: %s", debugW.Body.String())
}