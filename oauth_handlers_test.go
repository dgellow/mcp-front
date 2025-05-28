package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewOAuthServer(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL: Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	server, err := NewOAuthServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	if server.provider == nil {
		t.Error("OAuth provider not initialized")
	}

	if server.storage == nil {
		t.Error("Storage not initialized")
	}

	if server.config != config {
		t.Error("Config not properly stored")
	}
}

func TestWellKnownHandler(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL: Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	server, err := NewOAuthServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	server.WellKnownHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	var metadata ServerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if metadata.Issuer != config.Issuer {
		t.Errorf("Expected issuer '%s', got '%s'", config.Issuer, metadata.Issuer)
	}

	if metadata.AuthorizationEndpoint != config.Issuer+"/authorize" {
		t.Errorf("Expected authorization endpoint '%s/authorize', got '%s'", config.Issuer, metadata.AuthorizationEndpoint)
	}

	if metadata.TokenEndpoint != config.Issuer+"/token" {
		t.Errorf("Expected token endpoint '%s/token', got '%s'", config.Issuer, metadata.TokenEndpoint)
	}

	if !metadata.PKCERequired {
		t.Error("PKCE should be required")
	}

	expectedGrantTypes := []string{"authorization_code", "refresh_token"}
	if len(metadata.GrantTypesSupported) != len(expectedGrantTypes) {
		t.Errorf("Expected %d grant types, got %d", len(expectedGrantTypes), len(metadata.GrantTypesSupported))
	}

	expectedCodeChallengeMethods := []string{"S256"}
	if len(metadata.CodeChallengeMethodsSupported) != len(expectedCodeChallengeMethods) {
		t.Errorf("Expected %d code challenge methods, got %d", len(expectedCodeChallengeMethods), len(metadata.CodeChallengeMethodsSupported))
	}
}

func TestRegisterHandler(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL: Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	server, err := NewOAuthServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
	}{
		{
			name:           "valid registration",
			method:         "POST",
			body:           `{"redirect_uris": ["https://client.example.com/callback"], "scope": "read write"}`,
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "invalid method",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			body:           `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/register", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.RegisterHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusCreated {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}

				if _, exists := response["client_id"]; !exists {
					t.Error("Response should contain client_id")
				}

				if _, exists := response["client_secret"]; !exists {
					t.Error("Response should contain client_secret")
				}

				if redirectURIs, exists := response["redirect_uris"]; !exists {
					t.Error("Response should contain redirect_uris")
				} else if uris, ok := redirectURIs.([]interface{}); !ok || len(uris) == 0 {
					t.Error("redirect_uris should be a non-empty array")
				}
			}
		})
	}
}

func TestAuthorizeHandler(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL: Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	server, err := NewOAuthServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	// First, create a client
	metadata := map[string]interface{}{
		"redirect_uris": []interface{}{"https://client.example.com/callback"},
		"scope":         "read",
	}
	client, err := server.storage.CreateClient(context.Background(), metadata)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	tests := []struct {
		name        string
		queryParams string
		expectError bool
	}{
		{
			name:        "missing required parameters",
			queryParams: "",
			expectError: true,
		},
		{
			name:        "invalid client",
			queryParams: "?response_type=code&client_id=invalid&redirect_uri=https://client.example.com/callback&code_challenge=test&code_challenge_method=S256",
			expectError: true,
		},
		{
			name:        "valid request",
			queryParams: "?response_type=code&client_id=" + client.GetID() + "&redirect_uri=https://client.example.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256&scope=read&state=12345678901234567890",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/authorize"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			server.AuthorizeHandler(w, req)

			if tt.expectError {
				// Should return an error response (400 or similar)
				if w.Code >= 200 && w.Code < 300 {
					t.Errorf("Expected error status, got %d", w.Code)
				}
			} else {
				// Should redirect to Google OAuth (302)
				if w.Code != http.StatusFound {
					t.Errorf("Expected status 302 (redirect), got %d", w.Code)
				}

				location := w.Header().Get("Location")
				if location == "" {
					t.Error("Expected Location header for redirect")
				}

				if !strings.Contains(location, "accounts.google.com") {
					t.Errorf("Expected redirect to Google OAuth, got: %s", location)
				}
			}
		})
	}
}

func TestValidateTokenMiddleware(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL: Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	server, err := NewOAuthServer(config)
	if err != nil {
		t.Fatalf("Failed to create OAuth server: %v", err)
	}

	middleware := server.ValidateTokenMiddleware()

	// Create a simple handler to wrap
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := middleware(handler)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "no authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid token",
			authHeader:     "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed header",
			authHeader:     "InvalidFormat",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}