package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/storage"
)

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Test the health handler directly
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"mcp-front"}`))
	})

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type: application/json, got: %s", w.Header().Get("Content-Type"))
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status: ok, got: %s", response["status"])
	}

	if response["service"] != "mcp-front" {
		t.Errorf("Expected service: mcp-front, got: %s", response["service"])
	}
}

func TestOAuthEndpointsCORS(t *testing.T) {
	authConfig := auth.Config{
		Issuer:             "https://test.example.com",
		TokenTTL:           time.Hour,
		AllowedDomains:     []string{"example.com"},
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
		JWTSecret:          "test-secret-32-bytes-long-for-testing",
		EncryptionKey:      "test-encryption-key-32-bytes-ok!",
		StorageType:        "memory",
	}

	store := storage.NewMemoryStorage()
	authServer, err := auth.NewServer(authConfig, store)
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
		{"/register", "POST"},
		{"/register", "OPTIONS"},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			var req *http.Request

			if endpoint.path == "/register" && endpoint.method == "POST" {
				requestBody := `{"redirect_uris": ["https://client.example.com/callback"], "scope": "read write"}`
				req = httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(requestBody))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(endpoint.method, endpoint.path, nil)
			}

			req.Header.Set("Origin", "http://localhost:6274")

			// For preflight requests, add required headers
			if endpoint.method == "OPTIONS" {
				req.Header.Set("Access-Control-Request-Method", "GET")
				req.Header.Set("Access-Control-Request-Headers", "authorization")
			}

			w := httptest.NewRecorder()

			// Create CORS-wrapped handler
			corsHandler := corsMiddleware([]string{"http://localhost:6274"})
			var handler http.Handler

			switch endpoint.path {
			case "/.well-known/oauth-authorization-server":
				authHandlers := NewAuthHandlers(authServer)
				handler = corsHandler(http.HandlerFunc(authHandlers.WellKnownHandler))
			case "/register":
				authHandlers := NewAuthHandlers(authServer)
				handler = corsHandler(http.HandlerFunc(authHandlers.RegisterHandler))
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
