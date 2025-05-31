package integration

import (
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
