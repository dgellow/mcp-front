package integration

import (
	"net/http"
	"os"
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
	mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", "config/config.test.json")
	mcpCmd.Env = append(mcpCmd.Environ(),
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	)

	// Pass through LOG_LEVEL and LOG_FORMAT if set
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		mcpCmd.Env = append(mcpCmd.Env, "LOG_LEVEL="+logLevel)
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		mcpCmd.Env = append(mcpCmd.Env, "LOG_FORMAT="+logFormat)
	}

	// Capture output to log file if MCP_LOG_FILE is set
	if logFile := os.Getenv("MCP_LOG_FILE"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			mcpCmd.Stderr = f
			mcpCmd.Stdout = f
			t.Cleanup(func() { f.Close() })
		}
	}

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	// Ensure mcp-front is stopped on cleanup
	t.Cleanup(func() {
		if mcpCmd.Process != nil {
			_ = mcpCmd.Process.Kill()
			_ = mcpCmd.Wait()
		}
	})

	// Check if process exited immediately (e.g., due to config error)
	processDone := make(chan error, 1)
	go func() {
		processDone <- mcpCmd.Wait()
	}()

	// Wait for server to be ready or fail
	select {
	case err := <-processDone:
		// Process exited early
		trace(t, "mcp-front process exited with error: %v", err)
		if logFile := os.Getenv("MCP_LOG_FILE"); logFile != "" {
			if content, readErr := os.ReadFile(logFile); readErr == nil && len(content) > 0 {
				t.Logf("mcp-front output:\n%s", string(content))
			}
		}
		t.Fatalf("mcp-front exited unexpectedly: %v", err)
	case <-time.After(2 * time.Second):
		// Process is still running, check if it's actually ready
		trace(t, "mcp-front process still running, checking if ready")
		if !waitForServer(t, 10) {
			t.Fatalf("mcp-front failed to become ready")
		}
		trace(t, "mcp-front is ready")
	}

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

// waitForServer waits for the server to be ready by checking /health endpoint
func waitForServer(t *testing.T, maxSeconds int) bool {
	for i := 0; i < maxSeconds; i++ {
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
