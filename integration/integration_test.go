package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration validates the complete end-to-end architecture
func TestIntegration(t *testing.T) {
	trace(t, "Starting integration test")

	// Database is already started by TestMain, just wait for readiness
	trace(t, "Waiting for database readiness")
	waitForDB(t)

	// Start mock GCP server
	// Starting mock GCP server
	mockGCP := NewMockGCPServer("9090")
	err := mockGCP.Start()
	require.NoError(t, err, "Failed to start mock GCP server")
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
	require.NotNil(t, client, "Failed to create MCP client")
	defer client.Close() // Ensure SSE connection is closed

	// Authenticate
	err = client.Authenticate()
	require.NoError(t, err, "Authentication failed")

	// For stdio transports, we need to use the proper session-based approach
	t.Log("Testing stdio MCP server...")

	// Connect to the SSE endpoint - this will establish a session
	err = client.Connect()
	require.NoError(t, err, "Failed to connect to MCP server")

	t.Log("Connected to MCP server with session")

	// Test database query
	queryParams := map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"sql": "SELECT COUNT(*) as user_count FROM users",
		},
	}

	result, err := client.SendMCPRequest("tools/call", queryParams)
	require.NoError(t, err, "Failed to execute query")

	t.Logf("Query result: %+v", result)

	// Verify we got a successful response
	require.NotNil(t, result, "Expected some response from MCP server")

	// Check for error in response
	errorMap, hasError := result["error"].(map[string]interface{})
	assert.False(t, hasError, "Query returned error: %v", errorMap)

	// Verify we got result content
	resultMap, ok := result["result"].(map[string]interface{})
	require.True(t, ok, "Expected result in response")

	content, ok := resultMap["content"].([]interface{})
	require.True(t, ok, "Expected content in result")
	assert.NotEmpty(t, content, "Query result missing content")
	t.Log("Query executed successfully")

	// Test resources list
	resourcesResult, err := client.SendMCPRequest("resources/list", map[string]interface{}{})
	require.NoError(t, err, "Failed to list resources")

	t.Logf("Resources response: %+v", resourcesResult)

	// Check for error in resources response
	errorMap, hasError = resourcesResult["error"].(map[string]interface{})
	assert.False(t, hasError, "Resources list returned error: %v", errorMap)

	// Verify we got resources
	resultMap, ok = resourcesResult["result"].(map[string]interface{})
	require.True(t, ok, "Expected result in resources response")

	resources, ok := resultMap["resources"].([]interface{})
	require.True(t, ok, "Expected resources array in result")
	assert.NotEmpty(t, resources, "Expected at least one resource")
	t.Logf("Found %d resources", len(resources))

}
