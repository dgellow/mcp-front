package integration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInlineMCPServer tests the inline MCP server functionality
func TestInlineMCPServer(t *testing.T) {
	trace(t, "Starting inline MCP server test")

	// Set environment variable for testing
	os.Setenv("INLINE_TEST_ENV_VAR", "env-value-456")
	defer os.Unsetenv("INLINE_TEST_ENV_VAR")

	trace(t, "Starting mcp-front with inline config")
	mcpCmd := startMCPFront(t, "config/config.inline-test.json")
	defer stopMCPFront(mcpCmd)

	waitForMCPFront(t)
	trace(t, "mcp-front is ready")

	client := NewMCPClient("http://localhost:8080")
	require.NotNil(t, client, "Failed to create MCP client")
	defer client.Close()

	client.SetAuthToken("inline-test-token")

	// Connect to the inline server SSE endpoint - need custom connection
	err := client.ConnectToServer("test-inline")
	require.NoError(t, err, "Failed to connect to inline MCP server")

	t.Log("Connected to inline MCP server")

	// Test 1: Basic echo tool
	t.Run("echo tool", func(t *testing.T) {
		params := map[string]interface{}{
			"name": "echo",
			"arguments": map[string]interface{}{
				"message": "Hello, inline MCP!",
			},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call echo tool")

		// Check for error in response
		errorMap, hasError := result["error"].(map[string]interface{})
		assert.False(t, hasError, "Echo tool returned error: %v", errorMap)

		// Verify result
		resultMap, ok := result["result"].(map[string]interface{})
		require.True(t, ok, "Expected result in response")

		content, ok := resultMap["content"].([]interface{})
		require.True(t, ok, "Expected content in result")
		require.NotEmpty(t, content, "Expected content array")

		firstContent, ok := content[0].(map[string]interface{})
		require.True(t, ok, "Expected content item to be map")

		text, ok := firstContent["text"].(string)
		require.True(t, ok, "Expected text in content")
		assert.Contains(t, text, "Hello, inline MCP!")
	})

	// Test 2: Environment variables
	t.Run("environment variables", func(t *testing.T) {
		params := map[string]interface{}{
			"name":      "env_test",
			"arguments": map[string]interface{}{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call env_test tool")

		// Check result
		resultMap, _ := result["result"].(map[string]interface{})
		content, _ := resultMap["content"].([]interface{})
		firstContent, _ := content[0].(map[string]interface{})
		text, _ := firstContent["text"].(string)

		// printenv outputs all environment variables
		assert.Contains(t, text, "TEST_VAR=test-value-123", "Static env var not set correctly")
		assert.Contains(t, text, "OTHER_VAR=env-value-456", "Dynamic env var not resolved correctly")
	})

	// Test 3: Template substitution
	t.Run("template substitution", func(t *testing.T) {
		params := map[string]interface{}{
			"name": "template_test",
			"arguments": map[string]interface{}{
				"name":  "TestUser",
				"count": 42,
			},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call template_test tool")

		// Check result
		resultMap, _ := result["result"].(map[string]interface{})
		content, _ := resultMap["content"].([]interface{})
		firstContent, _ := content[0].(map[string]interface{})
		text, _ := firstContent["text"].(string)

		assert.Contains(t, text, "Name: TestUser")
		assert.Contains(t, text, "Count: 42")
		assert.NotContains(t, text, "Optional:", "Optional field should not appear when not provided")
	})

	// Test 4: Template with optional field
	t.Run("template with optional", func(t *testing.T) {
		params := map[string]interface{}{
			"name": "template_test",
			"arguments": map[string]interface{}{
				"name":     "TestUser",
				"count":    42,
				"optional": "extra-data",
			},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call template_test tool with optional")

		// Check result
		resultMap, _ := result["result"].(map[string]interface{})
		content, _ := resultMap["content"].([]interface{})
		firstContent, _ := content[0].(map[string]interface{})
		text, _ := firstContent["text"].(string)

		assert.Contains(t, text, "Optional: extra-data")
	})

	// Test 5: JSON output parsing
	t.Run("JSON output", func(t *testing.T) {
		params := map[string]interface{}{
			"name": "json_output",
			"arguments": map[string]interface{}{
				"value": "test-input",
			},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call json_output tool")

		// For JSON output, the content should be parsed as JSON
		resultMap, _ := result["result"].(map[string]interface{})
		content, _ := resultMap["content"].([]interface{})
		firstContent, _ := content[0].(map[string]interface{})

		// The JSON output should be in the text field as a string
		text, ok := firstContent["text"].(string)
		require.True(t, ok, "Expected text in content for JSON output")

		// Use testify's JSON assertions
		expectedJSON := `{"status":"ok","input":"test-input","timestamp":1234567890}`
		assert.JSONEq(t, expectedJSON, text)
	})

	// Test 6: Error handling
	t.Run("failing tool", func(t *testing.T) {
		params := map[string]interface{}{
			"name":      "failing_tool",
			"arguments": map[string]interface{}{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Request should succeed even if tool fails")

		// Check for error in response
		errorMap, hasError := result["error"].(map[string]interface{})
		assert.True(t, hasError, "Expected error for failing tool")

		if hasError {
			code, _ := errorMap["code"].(float64)
			assert.Equal(t, float64(-32603), code, "Expected internal error code")

			message, _ := errorMap["message"].(string)
			assert.Contains(t, message, "command failed")
		}
	})

	// Test 7: List tools
	t.Run("list tools", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/list", map[string]interface{}{})
		require.NoError(t, err, "Failed to list tools")

		// Check result
		resultMap, ok := result["result"].(map[string]interface{})
		require.True(t, ok, "Expected result in response")

		tools, ok := resultMap["tools"].([]interface{})
		require.True(t, ok, "Expected tools array")
		assert.Len(t, tools, 6, "Expected 6 tools")

		// Verify tool names
		toolNames := make([]string, 0)
		for _, tool := range tools {
			toolMap, _ := tool.(map[string]interface{})
			name, _ := toolMap["name"].(string)
			toolNames = append(toolNames, name)
		}

		assert.Contains(t, toolNames, "echo")
		assert.Contains(t, toolNames, "env_test")
		assert.Contains(t, toolNames, "template_test")
		assert.Contains(t, toolNames, "json_output")
		assert.Contains(t, toolNames, "failing_tool")
		assert.Contains(t, toolNames, "slow_tool")
	})
}
