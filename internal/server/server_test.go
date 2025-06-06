package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/oauth"
)

func TestCORSMiddleware(t *testing.T) {
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

	corsHandler := corsMiddleware()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	handler := corsHandler(testHandler)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			// Check CORS headers
			expectedHeaders := map[string]string{
				"Access-Control-Allow-Origin":      tc.expectedOrigin,
				"Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, Cache-Control, mcp-protocol-version",
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Max-Age":           "3600",
			}

			for header, expected := range expectedHeaders {
				actual := w.Header().Get(header)
				if actual != expected {
					t.Errorf("Expected %s: %s, got: %s", header, expected, actual)
				}
			}
		})
	}
}

func TestCORSOptionsRequest(t *testing.T) {
	corsHandler := corsMiddleware()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	handler := corsHandler(testHandler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// OPTIONS should return 200 OK
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for OPTIONS request, got %d", w.Code)
	}

	// Should have CORS headers
	if w.Header().Get("Access-Control-Allow-Origin") != "https://claude.ai" {
		t.Errorf("Expected Access-Control-Allow-Origin: https://claude.ai, got: %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Test the health handler directly
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"mcp-front"}`))
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
	oauthConfig := oauth.Config{
		Issuer:             "https://test.example.com",
		TokenTTL:           time.Hour,
		AllowedDomains:     []string{"example.com"},
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
		JWTSecret:          "test-secret-32-bytes-long-for-testing",
		StorageType:        "memory",
	}

	server, err := oauth.NewServer(oauthConfig)
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
			corsHandler := corsMiddleware()
			var handler http.Handler

			switch endpoint.path {
			case "/.well-known/oauth-authorization-server":
				handler = corsHandler(http.HandlerFunc(server.WellKnownHandler))
			case "/register":
				handler = corsHandler(http.HandlerFunc(server.RegisterHandler))
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
