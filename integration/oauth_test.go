package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"testing"
	"time"
)

// TestOAuthFlowIntegration contains comprehensive OAuth integration tests
func TestOAuthFlowIntegration(t *testing.T) {
	// Start test database
	t.Log("Starting test database for OAuth tests...")
	dbCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "up", "-d")
	if err := dbCmd.Run(); err != nil {
		t.Fatalf("Failed to start test database: %v", err)
	}

	// Ensure cleanup
	t.Cleanup(func() {
		t.Log("Cleaning up OAuth test environment...")
		downCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "down", "-v")
		if err := downCmd.Run(); err != nil {
			t.Logf("Warning: cleanup failed: %v", err)
		}
	})

	// Wait for database
	waitForDatabase(t)

	// Run OAuth test scenarios
	t.Run("JWTSecretValidation", testOAuthJWTSecretValidation)
	t.Run("ClientRegistration", testOAuthClientRegistration)
	t.Run("StateParameterHandling", testOAuthStateParameterHandling)
	t.Run("DevelopmentMode", testOAuthDevelopmentMode)
	t.Run("OAuthDiscovery", testOAuthEndpointDiscovery)
}

// testOAuthJWTSecretValidation tests JWT secret length requirements
func testOAuthJWTSecretValidation(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		shouldFail bool
	}{
		{"3-byte secret", "123", true},
		{"16-byte secret", "sixteen-byte-key", true},
		{"32-byte secret", "demo-jwt-secret-32-bytes-exactly!", false},
		{"33-byte secret", "demo-jwt-secret-32-bytes-exactly!x", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing JWT secret: %s (length: %d)", tt.name, len(tt.secret))
			
			// Start mcp-front with specific JWT secret
			mcpCmd := startMCPFrontOAuth(t, map[string]string{
				"JWT_SECRET": tt.secret,
				"MCP_FRONT_ENV": "development",
			})
			defer stopMCPFront(mcpCmd)

			// Wait for startup
			if !waitForMCPFront(t) {
				if tt.shouldFail {
					t.Log("Expected failure - mcp-front failed to start with invalid JWT secret")
					return // This is expected
				}
				t.Fatal("mcp-front failed to start")
			}

			// Try OAuth flow - register client
			clientResp := registerOAuthClient(t)
			if tt.shouldFail {
				t.Fatal("Expected OAuth flow to fail with invalid JWT secret")
			}

			// Try authorization flow
			authURL := startAuthFlow(t, clientResp.ClientID)
			t.Logf("Authorization URL created successfully: %s", authURL[:50]+"...")
		})
	}
}

// testOAuthClientRegistration tests dynamic client registration
func testOAuthClientRegistration(t *testing.T) {
	mcpCmd := startMCPFrontOAuth(t, map[string]string{
		"JWT_SECRET": "demo-jwt-secret-32-bytes-exactly!",
		"MCP_FRONT_ENV": "development",
	})
	defer stopMCPFront(mcpCmd)

	if !waitForMCPFront(t) {
		t.Fatal("mcp-front failed to start")
	}

	t.Run("ValidRegistration", func(t *testing.T) {
		clientResp := registerOAuthClient(t)
		
		// Verify client was created as public client
		if clientResp.ClientID == "" {
			t.Fatal("Client ID should not be empty")
		}
		if clientResp.ClientSecret != "" {
			t.Fatal("Public client should not have a secret")
		}
		if len(clientResp.RedirectURIs) == 0 {
			t.Fatal("Redirect URIs should not be empty")
		}
		
		t.Logf("Successfully registered public client: %s", clientResp.ClientID)
	})

	t.Run("MultipleRegistrations", func(t *testing.T) {
		// Test that multiple registrations create different clients
		client1 := registerOAuthClient(t)
		client2 := registerOAuthClient(t)
		
		if client1.ClientID == client2.ClientID {
			t.Fatal("Multiple registrations should create different client IDs")
		}
		
		t.Logf("Created distinct clients: %s and %s", client1.ClientID[:10], client2.ClientID[:10])
	})
}

// testOAuthStateParameterHandling tests state parameter validation and generation
func testOAuthStateParameterHandling(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		state       string
		expectError bool
	}{
		{"ProductionMissingState", "production", "", true},
		{"ProductionValidState", "production", "valid-state-parameter-123", false},
		{"DevelopmentMissingState", "development", "", false}, // Should generate state
		{"DevelopmentValidState", "development", "valid-state-parameter-123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpCmd := startMCPFrontOAuth(t, map[string]string{
				"JWT_SECRET": "demo-jwt-secret-32-bytes-exactly!",
				"MCP_FRONT_ENV": tt.environment,
			})
			defer stopMCPFront(mcpCmd)

			if !waitForMCPFront(t) {
				t.Fatal("mcp-front failed to start")
			}

			clientResp := registerOAuthClient(t)
			
			// Create authorization request with specific state
			params := url.Values{
				"response_type":         {"code"},
				"client_id":            {clientResp.ClientID},
				"code_challenge":       {"test-challenge"},
				"code_challenge_method": {"S256"},
				"redirect_uri":         {"http://127.0.0.1:6274/oauth/callback/debug"},
				"scope":                {"read write"},
			}
			if tt.state != "" {
				params.Set("state", tt.state)
			}

			authURL := fmt.Sprintf("http://localhost:8080/authorize?%s", params.Encode())
			
			resp, err := http.Get(authURL)
			if err != nil {
				t.Fatalf("Failed to make authorization request: %v", err)
			}
			defer resp.Body.Close()

			if tt.expectError {
				if resp.StatusCode < 400 {
					t.Fatalf("Expected error response, got status %d", resp.StatusCode)
				}
				t.Logf("Got expected error response: %d", resp.StatusCode)
			} else {
				if resp.StatusCode >= 400 {
					body, _ := io.ReadAll(resp.Body)
					t.Fatalf("Expected successful redirect, got status %d: %s", resp.StatusCode, string(body))
				}
				t.Logf("Authorization request handled successfully: %d", resp.StatusCode)
			}
		})
	}
}

// testOAuthDevelopmentMode tests development-specific features
func testOAuthDevelopmentMode(t *testing.T) {
	mcpCmd := startMCPFrontOAuth(t, map[string]string{
		"JWT_SECRET": "demo-jwt-secret-32-bytes-exactly!",
		"MCP_FRONT_ENV": "development",
	})
	defer stopMCPFront(mcpCmd)

	if !waitForMCPFront(t) {
		t.Fatal("mcp-front failed to start")
	}

	// Test that development mode allows weak state parameters
	clientResp := registerOAuthClient(t)
	
	// Authorization request without state parameter
	params := url.Values{
		"response_type":         {"code"},
		"client_id":            {clientResp.ClientID},
		"code_challenge":       {"test-challenge"},
		"code_challenge_method": {"S256"},
		"redirect_uri":         {"http://127.0.0.1:6274/oauth/callback/debug"},
		"scope":                {"read write"},
		// Intentionally omitting state parameter
	}

	authURL := fmt.Sprintf("http://localhost:8080/authorize?%s", params.Encode())
	
	resp, err := http.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to make authorization request: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to Google OAuth (not error)
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Development mode should handle missing state, got status %d: %s", resp.StatusCode, string(body))
	}

	t.Log("Development mode successfully handled missing state parameter")
}

// testOAuthEndpointDiscovery tests OAuth discovery endpoint
func testOAuthEndpointDiscovery(t *testing.T) {
	mcpCmd := startMCPFrontOAuth(t, map[string]string{
		"JWT_SECRET": "demo-jwt-secret-32-bytes-exactly!",
		"MCP_FRONT_ENV": "development",
	})
	defer stopMCPFront(mcpCmd)

	if !waitForMCPFront(t) {
		t.Fatal("mcp-front failed to start")
	}

	resp, err := http.Get("http://localhost:8080/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("Failed to fetch OAuth discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode discovery response: %v", err)
	}

	// Verify required OAuth endpoints
	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
	}

	for _, field := range requiredFields {
		if _, ok := discovery[field]; !ok {
			t.Errorf("Missing required field in discovery: %s", field)
		}
	}

	t.Logf("OAuth discovery successful with issuer: %v", discovery["issuer"])
}

// Helper types for OAuth responses
type ClientRegistrationResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scope"`
}

// Helper functions
func startMCPFrontOAuth(t *testing.T, env map[string]string) *exec.Cmd {
	// Build mcp-front
	buildCmd := exec.Command("go", "build", "-o", "mcp-front", ".")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build mcp-front: %v", err)
	}

	// Start mcp-front with OAuth config
	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.oauth-test.json")
	
	// Set environment variables with defaults for testing
	mcpCmd.Env = []string{
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth-tests",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth-tests",
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"MCP_FRONT_ENV=development",
	}
	
	// Override with provided env vars
	for key, value := range env {
		mcpCmd.Env = append(mcpCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Capture stderr for debugging
	stderrPipe, _ := mcpCmd.StderrPipe()
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			t.Logf("mcp-front: %s", scanner.Text())
		}
	}()

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	return mcpCmd
}

func stopMCPFront(mcpCmd *exec.Cmd) {
	if mcpCmd != nil && mcpCmd.Process != nil {
		mcpCmd.Process.Kill()
		mcpCmd.Wait()
	}
}

func waitForMCPFront(t *testing.T) bool {
	for i := 0; i < 30; i++ {
		resp, err := http.Get("http://localhost:8080/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func registerOAuthClient(t *testing.T) ClientRegistrationResponse {
	clientReq := map[string]interface{}{
		"redirect_uris": []string{"http://127.0.0.1:6274/oauth/callback/debug"},
		"scope":         "read write",
	}

	reqBody, _ := json.Marshal(clientReq)
	resp, err := http.Post(
		"http://localhost:8080/register",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Client registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	var clientResp ClientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&clientResp); err != nil {
		t.Fatalf("Failed to decode client response: %v", err)
	}

	return clientResp
}

func startAuthFlow(t *testing.T, clientID string) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":            {clientID},
		"code_challenge":       {"test-challenge"},
		"code_challenge_method": {"S256"},
		"redirect_uri":         {"http://127.0.0.1:6274/oauth/callback/debug"},
		"scope":                {"read write"},
		"state":                {"test-state-parameter"},
	}

	authURL := fmt.Sprintf("http://localhost:8080/authorize?%s", params.Encode())
	
	resp, err := http.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to make authorization request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Authorization request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return authURL
}

func waitForDatabase(t *testing.T) {
	t.Log("Waiting for database to be ready...")
	for i := 0; i < 60; i++ { // Increased timeout
		// Check if container is running first
		psCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "ps", "-q", "test-postgres")
		if output, err := psCmd.Output(); err != nil || len(output) == 0 {
			t.Logf("Container not yet running (attempt %d/60)", i+1)
			time.Sleep(1 * time.Second)
			continue
		}
		
		// Check if database is ready
		checkCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "exec", "-T", "test-postgres", "pg_isready", "-U", "testuser", "-d", "testdb")
		if err := checkCmd.Run(); err == nil {
			t.Log("Database is ready")
			return
		}
		t.Logf("Database not ready yet (attempt %d/60)", i+1)
		time.Sleep(1 * time.Second)
	}
	
	// Show logs for debugging
	logsCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "logs", "test-postgres")
	if output, err := logsCmd.Output(); err == nil {
		t.Logf("Database logs:\n%s", string(output))
	}
	
	t.Fatal("Database failed to become ready after 60 seconds")
}