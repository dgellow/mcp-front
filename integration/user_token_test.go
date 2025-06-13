package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/server"
)

func TestUserTokenFlow(t *testing.T) {
	// Setup test configuration using new types
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			BaseURL: "https://test.example.com",
			Addr:    ":8080",
			Name:    "test-proxy",
			Auth: &config.OAuthAuthConfig{
				Kind:               config.AuthKindOAuth,
				Issuer:             "https://test.example.com",
				GCPProject:         "test-project",
				GoogleClientID:     "test-client-id",
				GoogleClientSecret: "test-client-secret",
				GoogleRedirectURI:  "https://test.example.com/callback",
				AllowedDomains:     []string{"example.com"},
				TokenTTL:           "1h",
				Storage:            "memory",
				JWTSecret:          strings.Repeat("a", 32),
				EncryptionKey:      strings.Repeat("b", 32),
			},
		},
		MCPServers: map[string]*config.MCPClientConfig{
			"notion": {
				TransportType:     config.MCPClientTypeSSE,
				URL:               "https://notion-mcp.example.com",
				RequiresUserToken: true,
				TokenSetup: &config.TokenSetupConfig{
					DisplayName:  "Notion",
					Instructions: "Create a Notion integration token",
					HelpURL:      "https://developers.notion.com",
					TokenFormat:  "^secret_[a-zA-Z0-9]{43}$",
				},
			},
			"github": {
				TransportType:     config.MCPClientTypeSSE,
				URL:               "https://github-mcp.example.com",
				RequiresUserToken: true,
				TokenSetup: &config.TokenSetupConfig{
					DisplayName: "GitHub",
					Instructions: "Create a GitHub personal access token",
					HelpURL:     "https://github.com/settings/tokens",
				},
			},
		},
	}

	// Create server
	ctx := context.Background()
	handler, err := server.NewServer(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Create test OAuth token
	token := createTestOAuthToken(t, srv, "test@example.com")

	t.Run("ListTokensInitially", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/my/tokens", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		// Should show both services without tokens
		body := w.Body.String()
		if !strings.Contains(body, "Notion") {
			t.Error("Expected Notion service in response")
		}
		if !strings.Contains(body, "GitHub") {
			t.Error("Expected GitHub service in response")
		}
	})

	t.Run("SetTokenWithValidation", func(t *testing.T) {
		// Get CSRF token first
		req := httptest.NewRequest("GET", "/my/tokens", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Extract CSRF token from response
		csrfToken := extractCSRFToken(t, w.Body.String())

		// Try to set invalid Notion token
		form := url.Values{
			"token":      {"invalid-token"},
			"csrf_token": {csrfToken},
		}
		req = httptest.NewRequest("POST", "/my/tokens/notion", strings.NewReader(form.Encode()))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Should redirect with error
		if w.Code != http.StatusSeeOther {
			t.Fatalf("Expected redirect, got %d", w.Code)
		}
		location := w.Header().Get("Location")
		if !strings.Contains(location, "type=error") {
			t.Error("Expected error redirect")
		}

		// Get new CSRF token
		req = httptest.NewRequest("GET", "/my/tokens", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		csrfToken = extractCSRFToken(t, w.Body.String())

		// Set valid Notion token
		form = url.Values{
			"token":      {"secret_abcdefghijklmnopqrstuvwxyz0123456789012345"},
			"csrf_token": {csrfToken},
		}
		req = httptest.NewRequest("POST", "/my/tokens/notion", strings.NewReader(form.Encode()))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Should redirect with success
		if w.Code != http.StatusSeeOther {
			t.Fatalf("Expected redirect, got %d", w.Code)
		}
		location = w.Header().Get("Location")
		if !strings.Contains(location, "type=success") {
			t.Error("Expected success redirect")
		}
	})
}

// createTestOAuthToken is a placeholder - would need to be implemented
func createTestOAuthToken(t *testing.T, srv *httptest.Server, email string) string {
	// This would create a test token using the OAuth server
	// For now, return a dummy token
	return "test-token-" + email
}

// extractCSRFToken extracts the CSRF token from the HTML response
func extractCSRFToken(t *testing.T, html string) string {
	// Look for <input type="hidden" name="csrf_token" value="...">
	re := regexp.MustCompile(`<input[^>]+name="csrf_token"[^>]+value="([^"]+)"`)
	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		t.Fatal("CSRF token not found in response")
	}
	return matches[1]
}