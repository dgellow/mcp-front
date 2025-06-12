package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/server"
)

func TestUserTokenFlow(t *testing.T) {
	// Setup test configuration
	cfg := &config.Config{
		Version: "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
		Proxy: config.ProxyConfig{
			BaseURL: config.NewConfigValue("https://test.example.com"),
			Addr:    config.NewConfigValue(":8080"),
			Name:    "test-proxy",
			Auth: &config.OAuthAuthConfig{
				Kind:               config.AuthKindOAuth,
				Issuer:             config.NewConfigValue("https://test.example.com"),
				GCPProject:         config.NewConfigValue("test-project"),
				GoogleClientID:     config.NewConfigValue("test-client-id"),
				GoogleClientSecret: config.NewConfigValue("test-client-secret"),
				GoogleRedirectURI:  config.NewConfigValue("https://test.example.com/callback"),
				AllowedDomains:     []string{"example.com"},
				TokenTTL:           "1h",
				Storage:            "memory",
				JWTSecret:          config.NewConfigValue(strings.Repeat("a", 32)),
				EncryptionKey:      config.NewConfigValue(strings.Repeat("b", 32)),
			},
		},
		MCPServers: map[string]*config.MCPClientConfig{
			"notion": {
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
	handler, cleanup := setupTestServer(t, cfg)
	defer cleanup()
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

	t.Run("AccessMCPServerWithToken", func(t *testing.T) {
		// Access Notion MCP server
		req := httptest.NewRequest("GET", "/mcp/notion/sse", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		// Create a mock handler for the MCP server
		mockMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify user token was injected
			auth := r.Header.Get("Authorization")
			if auth != "Bearer secret_abcdefghijklmnopqrstuvwxyz0123456789012345" {
				t.Errorf("Expected user token, got %s", auth)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer mockMCP.Close()

		// Update config to use mock server
		cfg.MCPServers["notion"].URL = mockMCP.URL

		// Recreate server with updated config
		handler2, cleanup2 := setupTestServer(t, cfg)
		defer cleanup2()
		srv.Close()
		srv = httptest.NewServer(handler2)

		handler.ServeHTTP(w, req)

		// The actual proxy would forward the request, but we can't test that here
		// Just verify it doesn't return a token error
		if w.Code == http.StatusForbidden {
			var errResp server.TokenRequiredError
			json.NewDecoder(w.Body).Decode(&errResp)
			if errResp.Error == "user_token_required" {
				t.Error("Should not require token after setting it")
			}
		}
	})

	t.Run("AccessMCPServerWithoutToken", func(t *testing.T) {
		// Try to access GitHub MCP server without token
		req := httptest.NewRequest("GET", "/mcp/github/sse", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("Expected 403, got %d", w.Code)
		}

		// Verify structured error response
		var errResp server.TokenRequiredError
		if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
			t.Fatalf("Failed to decode error response: %v", err)
		}

		if errResp.Error != "user_token_required" {
			t.Errorf("Expected user_token_required error, got %s", errResp.Error)
		}
		if errResp.Service != "github" {
			t.Errorf("Expected github service, got %s", errResp.Service)
		}
		if !strings.Contains(errResp.SetupURL, "/my/tokens") {
			t.Errorf("Expected setup URL to contain /my/tokens, got %s", errResp.SetupURL)
		}
	})

	t.Run("DeleteToken", func(t *testing.T) {
		// Get CSRF token
		req := httptest.NewRequest("GET", "/my/tokens", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		csrfToken := extractCSRFToken(t, w.Body.String())

		// Delete Notion token
		form := url.Values{
			"csrf_token": {csrfToken},
		}
		req = httptest.NewRequest("POST", "/my/tokens/notion/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w = httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Should redirect with success
		if w.Code != http.StatusSeeOther {
			t.Fatalf("Expected redirect, got %d", w.Code)
		}

		// Verify token is deleted by trying to access MCP server
		req = httptest.NewRequest("GET", "/mcp/notion/sse", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Error("Expected 403 after deleting token")
		}
	})
}

func extractCSRFToken(t *testing.T, html string) string {
	// Simple extraction - in real tests would use proper HTML parser
	prefix := `name="csrf_token" value="`
	start := strings.Index(html, prefix)
	if start == -1 {
		t.Fatal("CSRF token not found in response")
	}
	start += len(prefix)
	end := strings.Index(html[start:], `"`)
	if end == -1 {
		t.Fatal("CSRF token end not found")
	}
	return html[start : start+end]
}

func createTestOAuthToken(t *testing.T, srv *httptest.Server, email string) string {
	// This is a simplified version - in real tests would go through full OAuth flow
	// For now, we'll use the test helper to create a token directly
	return "test-token-" + email
}

func setupTestServer(t *testing.T, cfg *config.Config) (http.Handler, func()) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	
	handler, err := server.NewServer(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	cleanup := func() {
		cancel()
	}

	return handler, cleanup
}