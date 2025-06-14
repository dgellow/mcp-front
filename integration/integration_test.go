package integration

import (
	"os/exec"
	"testing"
	"time"
)

// TestIntegration validates the complete end-to-end architecture
func TestIntegration(t *testing.T) {
	trace(t, "Starting integration test")

	// Start test database
	trace(t, "Starting test database")
	dbCmd := exec.Command("docker", "compose", "up", "-d")
	if err := dbCmd.Run(); err != nil {
		t.Fatalf("Failed to start test database: %v", err)
	}

	// Ensure cleanup
	t.Cleanup(func() {
		// Cleaning up test environment
		downCmd := exec.Command("docker", "compose", "down", "-v")
		if err := downCmd.Run(); err != nil {
			t.Logf("Warning: cleanup failed: %v", err)
		}
	})

	// Wait for database to be ready
	// Waiting for database to be ready
	time.Sleep(10 * time.Second)

	// Start mock GCP server
	// Starting mock GCP server
	mockGCP := NewMockGCPServer("9090")
	if err := mockGCP.Start(); err != nil {
		t.Fatalf("Failed to start mock GCP server: %v", err)
	}
	t.Cleanup(func() {
		_ = mockGCP.Stop()
	})

	// Start mcp-front
	trace(t, "Starting mcp-front")
	mcpCmd := startMCPFront(t, "config/config.test.json",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	)
	defer stopMCPFront(mcpCmd)

	// Wait for server to be ready
	waitForMCPFront(t)
	trace(t, "mcp-front is ready")

	// Create test client
	// Testing MCP communication
	client := NewMCPClient("http://localhost:8080")
	defer client.Close() // Ensure SSE connection is closed

	// Authenticate
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	// For stdio transports, we need to use the proper session-based approach
	t.Log("Testing stdio MCP server...")

	// Connect to the SSE endpoint - this will establish a session
	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect to MCP server: %v", err)
	}

	t.Log("✓ Connected to MCP server with session")

	// Test database query
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
	}

	// Test resources list
	resourcesResult, err := client.SendMCPRequest("resources/list", map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to list resources: %v", err)
	}

	t.Logf("Resources response: %+v", resourcesResult)

}

