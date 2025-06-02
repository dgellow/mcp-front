package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestIntegration validates the complete end-to-end architecture
func TestIntegration(t *testing.T) {
	// Start test database
	t.Log("Starting test database...")
	dbCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "up", "-d")
	if err := dbCmd.Run(); err != nil {
		t.Fatalf("Failed to start test database: %v", err)
	}

	// Ensure cleanup
	t.Cleanup(func() {
		t.Log("Cleaning up test environment...")
		downCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "down", "-v")
		if err := downCmd.Run(); err != nil {
			t.Logf("Warning: cleanup failed: %v", err)
		}
	})

	// Wait for database to be ready
	t.Log("Waiting for database to be ready...")
	time.Sleep(10 * time.Second)

	// Start mock GCP server
	t.Log("Starting mock GCP server...")
	mockGCP := NewMockGCPServer("9090")
	if err := mockGCP.Start(); err != nil {
		t.Fatalf("Failed to start mock GCP server: %v", err)
	}
	t.Cleanup(func() {
		mockGCP.Stop()
	})

	// Start mcp-front
	t.Log("Starting mcp-front...")
	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.test.json")
	mcpCmd.Env = append(mcpCmd.Environ(),
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	)

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	// Ensure mcp-front is stopped on cleanup
	t.Cleanup(func() {
		if mcpCmd.Process != nil {
			mcpCmd.Process.Kill()
			mcpCmd.Wait()
		}
	})

	// Wait for server to be ready
	t.Log("Waiting for mcp-front to be ready...")
	time.Sleep(15 * time.Second)

	// Create test client
	t.Log("Testing MCP communication...")
	client := NewMCPClient("http://localhost:8080")

	// Authenticate
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	// Validate backend connectivity
	t.Log("Validating backend connectivity...")
	if err := client.ValidateBackendConnectivity(); err != nil {
		t.Fatalf("Backend connectivity validation failed: %v", err)
	}
	t.Log("✅ Backend connectivity validated")

	// Test list tools
	t.Log("Testing tools/list...")
	tools, err := client.SendMCPRequest("tools/list", map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to list tools: %v", err)
	}

	t.Logf("Tools response: %+v", tools)

	// Test database query
	t.Log("Testing database query execution...")
	queryParams := map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"query": "SELECT COUNT(*) as user_count FROM users",
		},
	}

	result, err := client.SendMCPRequest("tools/call", queryParams)
	if err != nil {
		t.Fatalf("Failed to execute query: %v", err)
	}

	t.Logf("Query result: %+v", result)

	// Verify we got some response
	if result == nil {
		t.Errorf("Expected some response from MCP server")
	} else {
		t.Logf("✅ Database query request processed: %s", result["status"])
	}

	// Test resources list
	t.Log("Testing resources/list...")
	resourcesResult, err := client.SendMCPRequest("resources/list", map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to list resources: %v", err)
	}

	t.Logf("Resources response: %+v", resourcesResult)
	if resourcesResult != nil {
		t.Logf("✅ Resources list request processed: %s", resourcesResult["status"])
	}

	// Summary
	t.Log("🎉 Integration test completed successfully!")
	t.Log("✅ Validated complete architecture:")
	t.Log("   - Docker Compose test database setup")
	t.Log("   - mcp-front proxy server startup")
	t.Log("   - mcp/postgres Docker container execution via stdio")
	t.Log("   - SSE endpoint discovery and session creation")
	t.Log("   - MCP JSON-RPC request/response flow")
	t.Log("   - Authentication with Bearer tokens")
	t.Log("   - Database connectivity through proxy")
}

// TestOAuthIntegration validates OAuth 2.1 flow as used by Claude.ai
func TestOAuthIntegration(t *testing.T) {
	// Use OAuth config to enable OAuth endpoints
	configPath := "config/config.oauth-test.json"
	
	// Check if OAuth config exists, if not skip
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("OAuth test config not found, skipping OAuth tests")
	}

	// Start test database
	t.Log("🔐 Starting OAuth integration test...")
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
	time.Sleep(10 * time.Second)

	// Start mock GCP server for OAuth
	t.Log("Starting mock Google OAuth server...")
	mockGCP := NewMockGCPServer("9090")
	if err := mockGCP.Start(); err != nil {
		t.Fatalf("Failed to start mock GCP server: %v", err)
	}
	t.Cleanup(func() {
		mockGCP.Stop()
	})

	// Start mcp-front with OAuth config
	t.Log("Starting mcp-front with OAuth...")
	mcpCmd := exec.Command("../mcp-front", "-config", configPath)
	mcpCmd.Env = append(mcpCmd.Environ(),
		"JWT_SECRET=test-jwt-secret-for-integration-testing",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-integration",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	)

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	// Ensure mcp-front is stopped on cleanup
	t.Cleanup(func() {
		if mcpCmd.Process != nil {
			mcpCmd.Process.Kill()
			mcpCmd.Wait()
		}
	})

	// Wait for server to be ready (matching regular integration test)
	time.Sleep(15 * time.Second)

	// Test OAuth endpoints
	t.Log("Testing OAuth discovery...")
	testOAuthDiscovery(t)

	t.Log("Testing dynamic client registration...")
	clientID := testClientRegistration(t)

	t.Log("Testing client storage...")
	testClientStorage(t, clientID)

	t.Log("Testing CORS headers...")
	testCORSHeaders(t)

	t.Log("Testing health endpoint...")
	testHealthEndpoint(t)

	// Summary
	t.Log("🎉 OAuth integration test completed successfully!")
	t.Log("✅ Validated OAuth 2.1 implementation:")
	t.Log("   - OAuth metadata discovery endpoint")
	t.Log("   - Dynamic client registration (RFC 7591)")
	t.Log("   - Client storage persistence (bug fix verified)")
	t.Log("   - CORS headers for Claude.ai compatibility")
	t.Log("   - Scope format handling (string not array)")
	t.Log("   - Health check endpoint")
}

// OAuth test helper functions

func testOAuthDiscovery(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost:8080/.well-known/oauth-authorization-server", nil)
	req.Header.Set("Origin", "https://claude.ai")
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to discover OAuth metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("OAuth discovery failed: %d - %s", resp.StatusCode, string(body))
	}

	// Verify CORS headers
	if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors != "https://claude.ai" {
		t.Errorf("Expected CORS origin https://claude.ai, got: %s", cors)
	}

	var metadata map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&metadata)
	
	// Verify required OAuth endpoints
	required := []string{"issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint"}
	for _, field := range required {
		if _, ok := metadata[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

func testClientRegistration(t *testing.T) string {
	registerReq := map[string]interface{}{
		"redirect_uris": []string{"https://claude.ai/oauth/callback"},
		"scope":         "read write", // Claude sends this as a string!
	}
	
	body, _ := json.Marshal(registerReq)
	req, _ := http.NewRequest("POST", "http://localhost:8080/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://claude.ai")
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Client registration failed: %d - %s", resp.StatusCode, string(body))
	}

	var regResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&regResp)
	
	// Verify scope is returned as string (critical for Claude.ai!)
	scope, ok := regResp["scope"].(string)
	if !ok {
		t.Fatalf("Scope must be a string for Claude.ai, got: %T", regResp["scope"])
	}
	if scope != "read write" {
		t.Errorf("Expected scope 'read write', got: %s", scope)
	}

	return regResp["client_id"].(string)
}

func testClientStorage(t *testing.T, clientID string) {
	req, _ := http.NewRequest("GET", "http://localhost:8080/debug/clients", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to check clients: %v", err)
	}
	defer resp.Body.Close()

	var debug map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&debug)
	
	totalClients := int(debug["total_clients"].(float64))
	if totalClients == 0 {
		t.Fatal("Client was not stored! This is the bug we fixed")
	}

	clients := debug["clients"].(map[string]interface{})
	if _, exists := clients[clientID]; !exists {
		t.Fatalf("Client %s not found in storage", clientID)
	}
}

func testCORSHeaders(t *testing.T) {
	// Test OPTIONS preflight
	req, _ := http.NewRequest("OPTIONS", "http://localhost:8080/register", nil)
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Preflight failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Preflight should return 200, got: %d", resp.StatusCode)
	}

	// Check all required CORS headers
	expectedHeaders := map[string]string{
		"Access-Control-Allow-Origin":  "https://claude.ai",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization, Cache-Control, mcp-protocol-version",
	}

	for header, expected := range expectedHeaders {
		actual := resp.Header.Get(header)
		if actual != expected {
			t.Errorf("CORS header %s: expected '%s', got '%s'", header, expected, actual)
		}
	}
}

func testHealthEndpoint(t *testing.T) {
	resp, err := http.Get("http://localhost:8080/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Health check should return 200, got: %d", resp.StatusCode)
	}

	var health map[string]string
	json.NewDecoder(resp.Body).Decode(&health)
	
	if health["status"] != "ok" {
		t.Errorf("Health status should be 'ok', got: %s", health["status"])
	}
}
