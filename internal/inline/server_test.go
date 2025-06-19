package inline

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_GetCapabilities(t *testing.T) {
	config := Config{
		Description: "Test server",
		Tools: []ToolConfig{
			{
				Name:        "echo",
				Description: "Echo a message",
				InputSchema: json.RawMessage(`{"type": "object", "properties": {"message": {"type": "string"}}}`),
			},
			{
				Name:        "date",
				Description: "Get current date",
				InputSchema: json.RawMessage(`{"type": "object"}`),
			},
		},
	}

	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "echo",
			Description: "Echo a message",
			InputSchema: json.RawMessage(`{"type": "object", "properties": {"message": {"type": "string"}}}`),
			Command:     "echo",
			Args:        []string{"{{.message}}"},
		},
		{
			Name:        "date",
			Description: "Get current date",
			InputSchema: json.RawMessage(`{"type": "object"}`),
			Command:     "date",
		},
	}

	server := NewServer("test", config, resolvedTools)
	capabilities := server.GetCapabilities()

	assert.Len(t, capabilities.Tools, 2)
	
	echoTool, exists := capabilities.Tools["echo"]
	assert.True(t, exists)
	assert.Equal(t, "echo", echoTool.Name)
	assert.Equal(t, "Echo a message", echoTool.Description)
	assert.NotNil(t, echoTool.InputSchema)

	dateTool, exists := capabilities.Tools["date"]
	assert.True(t, exists)
	assert.Equal(t, "date", dateTool.Name)
	assert.Equal(t, "Get current date", dateTool.Description)
}

func TestServer_HandleToolCall(t *testing.T) {
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "echo",
			Description: "Echo a message",
			Command:     "echo",
			Args:        []string{"{{.message}}"},
		},
		{
			Name:        "cat",
			Description: "Cat a file",
			Command:     "cat",
			Args:        []string{"{{.file}}"},
		},
		{
			Name:        "env_test",
			Description: "Test environment",
			Command:     "sh",
			Args:        []string{"-c", "echo TEST_VAR=$TEST_VAR"},
			Env: map[string]string{
				"TEST_VAR": "test-value",
			},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)

	tests := []struct {
		name      string
		toolName  string
		args      map[string]interface{}
		wantError bool
		validate  func(t *testing.T, result interface{}, err error)
	}{
		{
			name:     "echo with message",
			toolName: "echo",
			args: map[string]interface{}{
				"message": "Hello, World!",
			},
			wantError: false,
			validate: func(t *testing.T, result interface{}, err error) {
				resultMap, ok := result.(map[string]interface{})
				require.True(t, ok)
				output := resultMap["output"].(string)
				assert.Contains(t, output, "Hello, World!")
			},
		},
		{
			name:     "echo with empty message",
			toolName: "echo",
			args: map[string]interface{}{
				"message": "",
			},
			wantError: false,
			validate: func(t *testing.T, result interface{}, err error) {
				resultMap, ok := result.(map[string]interface{})
				require.True(t, ok)
				output := resultMap["output"].(string)
				assert.Equal(t, "\n", output) // echo with no args prints newline
			},
		},
		{
			name:     "nonexistent tool",
			toolName: "nonexistent",
			args:     map[string]interface{}{},
			wantError: true,
			validate: func(t *testing.T, result interface{}, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "tool nonexistent not found")
			},
		},
		{
			name:     "cat nonexistent file",
			toolName: "cat",
			args: map[string]interface{}{
				"file": "/tmp/nonexistent-file-12345",
			},
			wantError: true,
			validate: func(t *testing.T, result interface{}, err error) {
				assert.Error(t, err)
				resultMap, ok := result.(map[string]interface{})
				require.True(t, ok)
				stderr := resultMap["stderr"].(string)
				assert.Contains(t, stderr, "No such file")
			},
		},
		{
			name:     "environment variable test",
			toolName: "env_test",
			args:     map[string]interface{}{},
			wantError: false,
			validate: func(t *testing.T, result interface{}, err error) {
				resultMap, ok := result.(map[string]interface{})
				require.True(t, ok)
				output := resultMap["output"].(string)
				assert.Contains(t, output, "TEST_VAR=test-value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := server.HandleToolCall(ctx, tt.toolName, tt.args)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, result, err)
			}
		})
	}
}

func TestServer_processTemplateArgs(t *testing.T) {
	server := &Server{}

	tests := []struct {
		name         string
		templateArgs []string
		args         map[string]interface{}
		want         []string
		wantError    bool
	}{
		{
			name:         "no templates",
			templateArgs: []string{"echo", "hello", "world"},
			args:         map[string]interface{}{},
			want:         []string{"echo", "hello", "world"},
		},
		{
			name:         "simple template",
			templateArgs: []string{"echo", "{{.message}}"},
			args:         map[string]interface{}{"message": "Hello!"},
			want:         []string{"echo", "Hello!"},
		},
		{
			name:         "multiple templates",
			templateArgs: []string{"curl", "-X", "{{.method}}", "{{.url}}"},
			args: map[string]interface{}{
				"method": "POST",
				"url":    "https://api.example.com",
			},
			want: []string{"curl", "-X", "POST", "https://api.example.com"},
		},
		{
			name:         "conditional template",
			templateArgs: []string{"gcloud", "compute", "instances", "list", "--project={{.project}}", "{{if .zone}}--zone={{.zone}}{{end}}"},
			args: map[string]interface{}{
				"project": "my-project",
				"zone":    "us-central1-a",
			},
			want: []string{"gcloud", "compute", "instances", "list", "--project=my-project", "--zone=us-central1-a"},
		},
		{
			name:         "conditional template with missing value",
			templateArgs: []string{"gcloud", "compute", "instances", "list", "--project={{.project}}", "{{if .zone}}--zone={{.zone}}{{end}}"},
			args: map[string]interface{}{
				"project": "my-project",
			},
			want: []string{"gcloud", "compute", "instances", "list", "--project=my-project"},
		},
		{
			name:         "invalid template",
			templateArgs: []string{"echo", "{{.message"},
			args:         map[string]interface{}{"message": "test"},
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := server.processTemplateArgs(tt.templateArgs, tt.args)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestServer_HandleToolCall_JSON(t *testing.T) {
	// Create a tool that outputs JSON
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "json_output",
			Description: "Output JSON",
			Command:     "echo",
			Args:        []string{`{"status": "ok", "value": 42}`},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)
	
	ctx := context.Background()
	result, err := server.HandleToolCall(ctx, "json_output", map[string]interface{}{})
	
	require.NoError(t, err)
	
	// Should parse as JSON
	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ok", resultMap["status"])
	assert.Equal(t, float64(42), resultMap["value"])
}

func TestServer_HandleToolCall_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	// Create a tool with a very short timeout
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "slow_command",
			Description: "Slow command",
			Command:     "sleep",
			Args:        []string{"5"},
			Timeout:     100 * 1000 * 1000, // 100ms in nanoseconds
		},
	}

	server := NewServer("test", Config{}, resolvedTools)
	
	ctx := context.Background()
	result, err := server.HandleToolCall(ctx, "slow_command", map[string]interface{}{})
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "command failed")
	
	// Check that we got a timeout-related error in stderr or error message
	if resultMap, ok := result.(map[string]interface{}); ok {
		stderr, _ := resultMap["stderr"].(string)
		errorMsg, _ := resultMap["error"].(string)
		// The actual error message varies by OS, but it should indicate termination
		assert.True(t, 
			strings.Contains(stderr, "signal") || 
			strings.Contains(stderr, "terminated") ||
			strings.Contains(stderr, "killed") ||
			strings.Contains(errorMsg, "signal") ||
			strings.Contains(errorMsg, "killed"),
			"Expected error to contain signal/terminated/killed, got stderr: %s, error: %s", stderr, errorMsg)
	}
}