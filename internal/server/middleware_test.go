package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCorsMiddleware(t *testing.T) {
	tests := []struct {
		name              string
		allowedOrigins    []string
		requestOrigin     string
		expectAllowOrigin string
		expectCredentials bool
		expectWildcard    bool
	}{
		{
			name:              "allowed origin",
			allowedOrigins:    []string{"https://claude.ai", "https://example.com"},
			requestOrigin:     "https://claude.ai",
			expectAllowOrigin: "https://claude.ai",
			expectCredentials: true,
		},
		{
			name:              "disallowed origin",
			allowedOrigins:    []string{"https://claude.ai", "https://example.com"},
			requestOrigin:     "https://evil.com",
			expectAllowOrigin: "",
			expectCredentials: false,
		},
		{
			name:              "no origin header",
			allowedOrigins:    []string{"https://claude.ai"},
			requestOrigin:     "",
			expectAllowOrigin: "",
			expectCredentials: false,
		},
		{
			name:              "empty allowed origins with origin",
			allowedOrigins:    []string{},
			requestOrigin:     "https://claude.ai",
			expectAllowOrigin: "*",
			expectWildcard:    true,
		},
		{
			name:              "empty allowed origins no origin",
			allowedOrigins:    []string{},
			requestOrigin:     "",
			expectAllowOrigin: "*",
			expectWildcard:    true,
		},
		{
			name:              "preflight request",
			allowedOrigins:    []string{"https://claude.ai"},
			requestOrigin:     "https://claude.ai",
			expectAllowOrigin: "https://claude.ai",
			expectCredentials: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that just returns 200 OK
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with CORS middleware
			corsHandler := corsMiddleware(tt.allowedOrigins)(handler)

			// Create request
			method := "GET"
			if tt.name == "preflight request" {
				method = "OPTIONS"
			}
			req := httptest.NewRequest(method, "/test", nil)
			if tt.requestOrigin != "" {
				req.Header.Set("Origin", tt.requestOrigin)
			}

			// Execute request
			rr := httptest.NewRecorder()
			corsHandler.ServeHTTP(rr, req)

			// Check Access-Control-Allow-Origin header
			if tt.expectAllowOrigin != "" {
				assert.Equal(t, tt.expectAllowOrigin, rr.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
			}

			// Check Access-Control-Allow-Credentials header
			if tt.expectCredentials {
				assert.Equal(t, "true", rr.Header().Get("Access-Control-Allow-Credentials"))
			} else if !tt.expectWildcard {
				// When using wildcard (*), credentials header should not be set
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Credentials"))
			}

			// Check that standard CORS headers are always set
			assert.Equal(t, "GET, POST, OPTIONS", rr.Header().Get("Access-Control-Allow-Methods"))
			assert.Equal(t, "Content-Type, Authorization, Cache-Control, mcp-protocol-version", rr.Header().Get("Access-Control-Allow-Headers"))
			assert.Equal(t, "3600", rr.Header().Get("Access-Control-Max-Age"))

			// For OPTIONS requests, check status code
			if method == "OPTIONS" {
				assert.Equal(t, http.StatusOK, rr.Code)
			}
		})
	}
}

func TestCorsMiddleware_CaseSensitivity(t *testing.T) {
	// Test that origin matching is case-sensitive
	allowedOrigins := []string{"https://Claude.AI"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := corsMiddleware(allowedOrigins)(handler)

	// Test with different case
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://claude.ai")

	rr := httptest.NewRecorder()
	corsHandler.ServeHTTP(rr, req)

	// Should not match due to case difference
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCorsMiddleware_MultipleOrigins(t *testing.T) {
	// Test with multiple allowed origins
	allowedOrigins := []string{
		"https://claude.ai",
		"https://app.claude.ai",
		"https://dev.claude.ai",
		"https://staging.claude.ai",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := corsMiddleware(allowedOrigins)(handler)

	// Test each allowed origin
	for _, origin := range allowedOrigins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", origin)

			rr := httptest.NewRecorder()
			corsHandler.ServeHTTP(rr, req)

			assert.Equal(t, origin, rr.Header().Get("Access-Control-Allow-Origin"))
			assert.Equal(t, "true", rr.Header().Get("Access-Control-Allow-Credentials"))
		})
	}
}
