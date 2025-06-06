package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestOAuthIntegration validates the complete OAuth 2.1 implementation
// This includes all OAuth flows, JWT validation, client registration,
// state parameter handling, and environment-specific behavior
func TestOAuthIntegration(t *testing.T) {
	// Start test database
	dbCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "up", "-d")
	if err := dbCmd.Run(); err != nil {
		t.Fatalf("Failed to start test database: %v", err)
	}

	// Ensure cleanup
	t.Cleanup(func() {
		downCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "down", "-v")
		if err := downCmd.Run(); err != nil {
			t.Logf("Warning: cleanup failed: %v", err)
		}
	})

	// Wait for database
	waitForDatabase(t)

	// Start mock GCP server for OAuth
	mockGCP := NewMockGCPServer("9090")
	if err := mockGCP.Start(); err != nil {
		t.Fatalf("Failed to start mock GCP server: %v", err)
	}
	t.Cleanup(func() {
		_ = mockGCP.Stop()
	})

	// Run all OAuth test scenarios
	t.Run("BasicOAuthFlow", testBasicOAuthFlow)
	t.Run("JWTSecretValidation", testJWTSecretValidation)
	t.Run("ClientRegistration", testClientRegistration)
	t.Run("StateParameterHandling", testStateParameterHandling)
	t.Run("DevelopmentVsProduction", testEnvironmentModes)
	t.Run("OAuthEndpoints", testOAuthEndpoints)
	t.Run("CORSHeaders", testCORSHeaders)
}

// testBasicOAuthFlow tests the basic OAuth server functionality
func testBasicOAuthFlow(t *testing.T) {
	// Build and start mcp-front with OAuth config
	buildCmd := exec.Command("go", "build", "-o", "mcp-front", "./cmd/mcp-front")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build mcp-front: %v", err)
	}

	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.oauth-test.json")
	mcpCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	}

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}
	defer func() {
		if mcpCmd.Process != nil {
			_ = mcpCmd.Process.Kill()
			_ = mcpCmd.Wait()
		}
	}()

	// Wait for startup
	if !waitForHealthCheck(t, 30) {
		t.Fatal("mcp-front failed to start")
	}

	// Test OAuth discovery
	resp, err := http.Get("http://localhost:8080/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("Failed to get OAuth discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("OAuth discovery failed with status %d", resp.StatusCode)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode discovery: %v", err)
	}

	// Verify required endpoints
	requiredEndpoints := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
	}

	for _, endpoint := range requiredEndpoints {
		if _, ok := discovery[endpoint]; !ok {
			t.Errorf("Missing required endpoint: %s", endpoint)
		}
	}
}

// testJWTSecretValidation tests JWT secret length requirements
func testJWTSecretValidation(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		shouldFail bool
	}{
		{"Short 3-byte secret", "123", true},
		{"Short 16-byte secret", "sixteen-byte-key", true},
		{"Valid 32-byte secret", "demo-jwt-secret-32-bytes-exactly!", false},
		{"Long 64-byte secret", "demo-jwt-secret-32-bytes-exactly!demo-jwt-secret-32-bytes-exactly!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build mcp-front
			buildCmd := exec.Command("go", "build", "-o", "mcp-front", "./cmd/mcp-front")
			buildCmd.Dir = ".."
			if err := buildCmd.Run(); err != nil {
				t.Fatalf("Failed to build mcp-front: %v", err)
			}

			// Start mcp-front with specific JWT secret
			mcpCmd := exec.Command("../mcp-front", "-config", "config/config.oauth-test.json")
			mcpCmd.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"JWT_SECRET=" + tt.secret,
				"GOOGLE_CLIENT_ID=test-client-id",
				"GOOGLE_CLIENT_SECRET=test-client-secret",
				"MCP_FRONT_ENV=development",
			}

			// Capture stderr
			stderrPipe, _ := mcpCmd.StderrPipe()
			scanner := bufio.NewScanner(stderrPipe)

			if err := mcpCmd.Start(); err != nil {
				t.Fatalf("Failed to start mcp-front: %v", err)
			}

			// Read stderr to check for errors
			errorFound := false
			go func() {
				for scanner.Scan() {
					line := scanner.Text()
					if contains(line, "JWT secret must be at least") {
						errorFound = true
					}
				}
			}()

			// Give it time to start or fail
			time.Sleep(2 * time.Second)

			// Check if it's running
			healthy := checkHealth()

			// Clean up
			if mcpCmd.Process != nil {
				_ = mcpCmd.Process.Kill()
				_ = mcpCmd.Wait()
			}

			if tt.shouldFail {
				if healthy && !errorFound {
					t.Error("Expected failure with short JWT secret but server started successfully")
				}
			} else {
				if !healthy {
					t.Error("Expected success with valid JWT secret but server failed to start")
				}
			}
		})
	}
}

// testClientRegistration tests dynamic client registration (RFC 7591)
func testClientRegistration(t *testing.T) {
	// Start OAuth server
	mcpCmd := startOAuthServer(t, map[string]string{
		"MCP_FRONT_ENV": "development",
	})
	defer stopServer(mcpCmd)

	if !waitForHealthCheck(t, 30) {
		t.Fatal("OAuth server failed to start")
	}

	t.Run("PublicClientRegistration", func(t *testing.T) {
		// Register a public client (no secret)
		clientReq := map[string]interface{}{
			"redirect_uris": []string{"http://127.0.0.1:6274/oauth/callback/debug"},
			"scope":         "read write",
		}

		body, _ := json.Marshal(clientReq)
		resp, err := http.Post(
			"http://localhost:8080/register",
			"application/json",
			bytes.NewBuffer(body),
		)
		if err != nil {
			t.Fatalf("Failed to register client: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 201 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Client registration failed with status %d: %s", resp.StatusCode, string(body))
		}

		var clientResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&clientResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response
		if clientResp["client_id"] == "" {
			t.Error("Client ID should not be empty")
		}
		if clientResp["client_secret"] != nil {
			t.Error("Public client should not have a secret")
		}
		if scope, ok := clientResp["scope"].(string); !ok || scope != "read write" {
			t.Errorf("Expected scope 'read write' as string, got: %v", clientResp["scope"])
		}
	})

	t.Run("MultipleRegistrations", func(t *testing.T) {
		// Register multiple clients and verify they get different IDs
		var clientIDs []string

		for i := 0; i < 3; i++ {
			clientReq := map[string]interface{}{
				"redirect_uris": []string{fmt.Sprintf("http://example.com/callback%d", i)},
				"scope":         "read",
			}

			body, _ := json.Marshal(clientReq)
			resp, err := http.Post(
				"http://localhost:8080/register",
				"application/json",
				bytes.NewBuffer(body),
			)
			if err != nil {
				t.Fatalf("Failed to register client %d: %v", i, err)
			}
			defer resp.Body.Close()

			var clientResp map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&clientResp)
			clientIDs = append(clientIDs, clientResp["client_id"].(string))
		}

		// Verify all IDs are unique
		for i := 0; i < len(clientIDs); i++ {
			for j := i + 1; j < len(clientIDs); j++ {
				if clientIDs[i] == clientIDs[j] {
					t.Errorf("Client IDs should be unique, but got duplicate: %s", clientIDs[i])
				}
			}
		}

	})
}

// testStateParameterHandling tests OAuth state parameter requirements
func testStateParameterHandling(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		state       string
		expectError bool
	}{
		{"Production without state", "production", "", true},
		{"Production with state", "production", "secure-random-state", false},
		{"Development without state", "development", "", false}, // Should auto-generate
		{"Development with state", "development", "test-state", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start server with specific environment
			mcpCmd := startOAuthServer(t, map[string]string{
				"MCP_FRONT_ENV": tt.environment,
			})
			defer stopServer(mcpCmd)

			if !waitForHealthCheck(t, 30) {
				t.Fatal("Server failed to start")
			}

			// Register a client first
			clientID := registerTestClient(t)

			// Create authorization request
			params := url.Values{
				"response_type":         {"code"},
				"client_id":             {clientID},
				"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
				"scope":                 {"read write"},
			}
			if tt.state != "" {
				params.Set("state", tt.state)
			}

			authURL := fmt.Sprintf("http://localhost:8080/authorize?%s", params.Encode())

			// Use a client that doesn't follow redirects
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Get(authURL)
			if err != nil {
				t.Fatalf("Authorization request failed: %v", err)
			}
			defer resp.Body.Close()

			if tt.expectError {
				// OAuth errors are returned as redirects with error parameters
				if resp.StatusCode == 302 || resp.StatusCode == 303 {
					location := resp.Header.Get("Location")
					if strings.Contains(location, "error=") {
					} else {
						t.Errorf("Expected error redirect for %s, got redirect without error", tt.name)
					}
				} else if resp.StatusCode >= 400 {
				} else {
					t.Errorf("Expected error for %s, got status %d", tt.name, resp.StatusCode)
				}
			} else {
				if resp.StatusCode == 302 || resp.StatusCode == 303 {
					location := resp.Header.Get("Location")
					if strings.Contains(location, "error=") {
						t.Errorf("Unexpected error redirect for %s: %s", tt.name, location)
					}
				} else if resp.StatusCode < 400 {
				} else {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected success for %s, got status %d: %s", tt.name, resp.StatusCode, string(body))
				}
			}
		})
	}
}

// testEnvironmentModes tests development vs production mode differences
func testEnvironmentModes(t *testing.T) {
	t.Run("DevelopmentMode", func(t *testing.T) {
		mcpCmd := startOAuthServer(t, map[string]string{
			"MCP_FRONT_ENV": "development",
		})
		defer stopServer(mcpCmd)

		if !waitForHealthCheck(t, 30) {
			t.Fatal("Server failed to start")
		}

		// In development mode, missing state should be auto-generated
		clientID := registerTestClient(t)

		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
			"code_challenge":        {"test-challenge"},
			"code_challenge_method": {"S256"},
			"scope":                 {"read"},
			// Intentionally omitting state parameter
		}

		// Use a client that doesn't follow redirects
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Get("http://localhost:8080/authorize?" + params.Encode())
		if err != nil {
			t.Fatalf("Failed to make auth request: %v", err)
		}
		defer resp.Body.Close()

		// Should redirect (302) not error
		if resp.StatusCode >= 400 && resp.StatusCode != 302 {
			t.Errorf("Development mode should handle missing state, got status %d", resp.StatusCode)
		}
	})

	t.Run("ProductionMode", func(t *testing.T) {
		mcpCmd := startOAuthServer(t, map[string]string{
			"MCP_FRONT_ENV": "production",
		})
		defer stopServer(mcpCmd)

		if !waitForHealthCheck(t, 30) {
			t.Fatal("Server failed to start")
		}

		// In production mode, state should be required
		clientID := registerTestClient(t)

		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
			"code_challenge":        {"test-challenge"},
			"code_challenge_method": {"S256"},
			"scope":                 {"read"},
			// Intentionally omitting state parameter
		}

		// Use a client that doesn't follow redirects
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Get("http://localhost:8080/authorize?" + params.Encode())
		if err != nil {
			t.Fatalf("Failed to make auth request: %v", err)
		}
		defer resp.Body.Close()

		// Should error - OAuth errors are returned as redirects
		if resp.StatusCode == 302 || resp.StatusCode == 303 {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "error=") {
			} else {
				t.Errorf("Expected error redirect in production mode, got redirect without error")
			}
		} else if resp.StatusCode >= 400 {
		} else {
			t.Errorf("Production mode should require state parameter, got status %d", resp.StatusCode)
		}
	})
}

// testOAuthEndpoints tests all OAuth endpoints comprehensively
func testOAuthEndpoints(t *testing.T) {
	mcpCmd := startOAuthServer(t, map[string]string{
		"MCP_FRONT_ENV": "development",
	})
	defer stopServer(mcpCmd)

	if !waitForHealthCheck(t, 30) {
		t.Fatal("Server failed to start")
	}

	t.Run("Discovery", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("Discovery request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("Discovery failed with status %d", resp.StatusCode)
		}

		var discovery map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
			t.Fatalf("Failed to decode discovery response: %v", err)
		}

		// Verify all required fields
		required := []string{
			"issuer",
			"authorization_endpoint",
			"token_endpoint",
			"registration_endpoint",
			"response_types_supported",
			"grant_types_supported",
			"code_challenge_methods_supported",
		}

		for _, field := range required {
			if _, ok := discovery[field]; !ok {
				t.Errorf("Missing required discovery field: %s", field)
			}
		}

	})

	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/health")
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Health check should return 200, got %d", resp.StatusCode)
		}

		var health map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
			t.Fatalf("Failed to decode health response: %v", err)
		}
		if health["status"] != "ok" {
			t.Errorf("Expected status 'ok', got '%s'", health["status"])
		}

	})
}

// testCORSHeaders tests CORS headers for Claude.ai compatibility
func testCORSHeaders(t *testing.T) {
	mcpCmd := startOAuthServer(t, map[string]string{
		"MCP_FRONT_ENV": "development",
	})
	defer stopServer(mcpCmd)

	if !waitForHealthCheck(t, 30) {
		t.Fatal("Server failed to start")
	}

	// Test preflight request
	req, _ := http.NewRequest("OPTIONS", "http://localhost:8080/register", nil)
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Preflight request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Preflight should return 200, got %d", resp.StatusCode)
	}

	// Check CORS headers
	expectedHeaders := map[string]string{
		"Access-Control-Allow-Origin":  "https://claude.ai",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization, Cache-Control, mcp-protocol-version",
	}

	for header, expected := range expectedHeaders {
		actual := resp.Header.Get(header)
		if actual != expected {
			t.Errorf("Expected %s: '%s', got '%s'", header, expected, actual)
		}
	}

}

// Helper functions

func startOAuthServer(t *testing.T, env map[string]string) *exec.Cmd {
	// Build mcp-front
	buildCmd := exec.Command("go", "build", "-o", "mcp-front", "./cmd/mcp-front")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build mcp-front: %v", err)
	}

	// Start with OAuth config
	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.oauth-test.json")

	// Set default environment
	mcpCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"GOOGLE_CLIENT_ID=test-client-id-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-oauth",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	}

	// Override with provided env
	for key, value := range env {
		mcpCmd.Env = append(mcpCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start OAuth server: %v", err)
	}

	return mcpCmd
}

func stopServer(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

func waitForHealthCheck(t *testing.T, seconds int) bool {
	for i := 0; i < seconds; i++ {
		if checkHealth() {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func checkHealth() bool {
	resp, err := http.Get("http://localhost:8080/health")
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return true
	}
	if resp != nil {
		resp.Body.Close()
	}
	return false
}

func registerTestClient(t *testing.T) string {
	clientReq := map[string]interface{}{
		"redirect_uris": []string{"http://127.0.0.1:6274/oauth/callback"},
		"scope":         "read write",
	}

	body, _ := json.Marshal(clientReq)
	resp, err := http.Post(
		"http://localhost:8080/register",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Client registration failed: %d - %s", resp.StatusCode, string(body))
	}

	var clientResp map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&clientResp)
	return clientResp["client_id"].(string)
}

func waitForDatabase(t *testing.T) {
	for i := 0; i < 60; i++ {
		// Check if container is running
		psCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "ps", "-q", "test-postgres")
		if output, err := psCmd.Output(); err != nil || len(output) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		// Check if database is ready
		checkCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "exec", "-T", "test-postgres", "pg_isready", "-U", "testuser", "-d", "testdb")
		if err := checkCmd.Run(); err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	t.Fatal("Database failed to become ready after 60 seconds")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && strings.Contains(s, substr))
}
