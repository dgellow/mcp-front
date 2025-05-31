package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOAuthEndpointsCORS(t *testing.T) {
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

	// Test endpoints that should have CORS headers
	endpoints := []struct {
		path   string
		method string
	}{
		{"/.well-known/oauth-authorization-server", "GET"},
		{"/.well-known/oauth-authorization-server", "OPTIONS"},
		{"/authorize", "GET"},
		{"/authorize", "OPTIONS"},
		{"/token", "POST"},
		{"/token", "OPTIONS"},
		{"/register", "POST"},
		{"/register", "OPTIONS"},
		{"/oauth/callback", "GET"},
		{"/oauth/callback", "OPTIONS"},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
			req.Header.Set("Origin", "http://localhost:6274")
			
			// For preflight requests, add required headers
			if endpoint.method == "OPTIONS" {
				req.Header.Set("Access-Control-Request-Method", "GET")
				req.Header.Set("Access-Control-Request-Headers", "authorization")
			}

			w := httptest.NewRecorder()

			// Create CORS-wrapped handler
			corsHandler := corsMiddleware()
			var handler http.Handler
			
			switch endpoint.path {
			case "/.well-known/oauth-authorization-server":
				handler = corsHandler(http.HandlerFunc(server.WellKnownHandler))
			case "/authorize":
				handler = corsHandler(http.HandlerFunc(server.AuthorizeHandler))
			case "/token":
				handler = corsHandler(http.HandlerFunc(server.TokenHandler))
			case "/register":
				handler = corsHandler(http.HandlerFunc(server.RegisterHandler))
			case "/oauth/callback":
				handler = corsHandler(http.HandlerFunc(server.GoogleCallbackHandler))
			default:
				t.Fatalf("Unknown endpoint: %s", endpoint.path)
			}

			handler.ServeHTTP(w, req)

			// Check CORS headers are present
			corsHeaders := map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:6274",
				"Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, Cache-Control, mcp-protocol-version",
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Max-Age":           "3600",
			}

			for header, expectedValue := range corsHeaders {
				actualValue := w.Header().Get(header)
				if actualValue != expectedValue {
					t.Errorf("Expected %s: %s, got: %s", header, expectedValue, actualValue)
				}
			}

			// OPTIONS requests should return 200 OK
			if endpoint.method == "OPTIONS" {
				if w.Code != http.StatusOK {
					t.Errorf("Expected OPTIONS request to return 200, got %d", w.Code)
				}
			}
		})
	}
}

func TestCORSWithDifferentOrigins(t *testing.T) {
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

	corsHandler := corsMiddleware()
	handler := corsHandler(http.HandlerFunc(server.WellKnownHandler))

	testCases := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{
			name:           "with specific origin",
			origin:         "https://claude.ai",
			expectedOrigin: "https://claude.ai",
		},
		{
			name:           "with localhost origin",
			origin:         "http://localhost:3000",
			expectedOrigin: "http://localhost:3000",
		},
		{
			name:           "without origin header",
			origin:         "",
			expectedOrigin: "*",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			actualOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if actualOrigin != tc.expectedOrigin {
				t.Errorf("Expected Access-Control-Allow-Origin: %s, got: %s", tc.expectedOrigin, actualOrigin)
			}
		})
	}
}

func TestCORSPreflightBlocksWithoutOrigin(t *testing.T) {
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

	corsHandler := corsMiddleware()
	handler := corsHandler(http.HandlerFunc(server.WellKnownHandler))

	// Test OPTIONS request (preflight)
	req := httptest.NewRequest("OPTIONS", "/.well-known/oauth-authorization-server", nil)
	// Deliberately not setting Origin header

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should still set CORS headers with wildcard origin
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Expected Access-Control-Allow-Origin: *, got: %s", w.Header().Get("Access-Control-Allow-Origin"))
	}

	// Should return 200 for OPTIONS
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for OPTIONS request, got %d", w.Code)
	}
}

func TestClientRegistrationScopeFormat(t *testing.T) {
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

	corsHandler := corsMiddleware()
	handler := corsHandler(http.HandlerFunc(server.RegisterHandler))

	// Test client registration request
	requestBody := `{"redirect_uris": ["https://client.example.com/callback"], "scope": "read write"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Verify scope is returned as a string, not an array
	scope, exists := response["scope"]
	if !exists {
		t.Error("Response should contain scope field")
	}

	scopeStr, ok := scope.(string)
	if !ok {
		t.Errorf("Scope should be a string, got %T: %v", scope, scope)
	}

	expectedScope := "read write"
	if scopeStr != expectedScope {
		t.Errorf("Expected scope '%s', got '%s'", expectedScope, scopeStr)
	}
}