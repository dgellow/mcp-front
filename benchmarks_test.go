package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func BenchmarkOAuthServerCreation(b *testing.B) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL:           Duration(time.Hour),
		Storage:            "memory",
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server, err := NewOAuthServer(config)
		if err != nil {
			b.Fatal(err)
		}
		_ = server
	}
}

func BenchmarkStateGeneration(b *testing.B) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL:           Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	storage, err := NewGCPIAMStorage(config)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := storage.GenerateState()
		if len(state) == 0 {
			b.Fatal("empty state generated")
		}
	}
}

func BenchmarkWellKnownEndpoint(b *testing.B) {
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
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()

		server.WellKnownHandler(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("Expected 200, got %d", w.Code)
		}
	}
}

func BenchmarkClientRegistration(b *testing.B) {
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
		b.Fatal(err)
	}

	requestBody := `{"redirect_uris": ["https://client.example.com/callback"], "scope": "read write"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/register", strings.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.RegisterHandler(w, req)

		if w.Code != http.StatusCreated {
			b.Fatalf("Expected 201, got %d", w.Code)
		}
	}
}

func BenchmarkConfigValidation(b *testing.B) {
	config := &Config{
		McpProxy: &MCPProxyConfig{
			BaseURL: "https://example.com",
			Addr:    ":8080",
			Name:    "Test Proxy",
		},
		OAuth: &OAuthConfig{
			Issuer:             "https://example.com",
			GCPProject:         "test-project",
			AllowedDomains:     []string{"example.com"},
			TokenTTL:           Duration(time.Hour),
			Storage:            "memory",
			GoogleClientID:     "test-client-id",
			GoogleClientSecret: "test-secret",
			GoogleRedirectURI:  "https://example.com/callback",
		},
		McpServers: map[string]*MCPClientConfig{
			"test1": {Command: "echo", Args: []string{"hello"}},
			"test2": {URL: "https://example.com/sse"},
			"test3": {Command: "docker", Args: []string{"run", "--rm", "-i", "nginx"}},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ValidateConfig(config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConfigSanitization(b *testing.B) {
	config := &Config{
		McpProxy: &MCPProxyConfig{
			BaseURL: "  https://example.com/  ",
			Addr:    "  :8080  ",
			Name:    "  Test Proxy  ",
		},
		OAuth: &OAuthConfig{
			Issuer:             "  https://example.com/  ",
			GCPProject:         "  test-project  ",
			AllowedDomains:     []string{"  Example.COM  ", "  TEST.com  "},
			GoogleClientID:     "  test-client-id  ",
			GoogleClientSecret: "  test-secret  ",
			GoogleRedirectURI:  "  https://example.com/callback  ",
		},
		McpServers: map[string]*MCPClientConfig{
			"test": {
				Command: "  echo  ",
				Args:    []string{"  hello  ", "  world  "},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Make a copy for each iteration since sanitization modifies in place
		testConfig := *config
		testConfig.McpProxy = &MCPProxyConfig{
			BaseURL: config.McpProxy.BaseURL,
			Addr:    config.McpProxy.Addr,
			Name:    config.McpProxy.Name,
		}
		SanitizeConfig(&testConfig)
	}
}

func BenchmarkTokenValidationMiddleware(b *testing.B) {
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
		b.Fatal(err)
	}

	middleware := server.ValidateTokenMiddleware()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := middleware(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)
		// We expect 401 since we're using an invalid token
	}
}

func BenchmarkAuthorizeRequestStateStorage(b *testing.B) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL:           Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	storage, err := NewGCPIAMStorage(config)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := storage.GenerateState()

		// Just benchmark state generation and storage operations
		// without complex fosite interface implementation
		if len(state) == 0 {
			b.Fatal("Empty state generated")
		}
	}
}

func BenchmarkClientCreation(b *testing.B) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL:           Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	storage, err := NewGCPIAMStorage(config)
	if err != nil {
		b.Fatal(err)
	}

	metadata := map[string]interface{}{
		"redirect_uris": []interface{}{
			"https://client.example.com/callback",
		},
		"scope": "read write",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := storage.CreateClient(context.Background(), metadata)
		if err != nil {
			b.Fatal(err)
		}
	}
}
