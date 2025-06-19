package inline

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveConfig(t *testing.T) {
	// Set up test environment variables
	os.Setenv("TEST_API_KEY", "secret-key-123")
	os.Setenv("TEST_ENDPOINT", "https://api.example.com")
	defer os.Unsetenv("TEST_API_KEY")
	defer os.Unsetenv("TEST_ENDPOINT")

	tests := []struct {
		name      string
		config    string
		wantError bool
		validate  func(t *testing.T, cfg Config, tools []ResolvedToolConfig)
	}{
		{
			name: "simple tool with no env vars",
			config: `{
				"description": "Test tools",
				"tools": [{
					"name": "echo",
					"description": "Echo a message",
					"inputSchema": {"type": "object"},
					"command": "echo",
					"args": ["hello", "world"]
				}]
			}`,
			wantError: false,
			validate: func(t *testing.T, cfg Config, tools []ResolvedToolConfig) {
				assert.Len(t, tools, 1)
				assert.Equal(t, "echo", tools[0].Name)
				assert.Equal(t, "echo", tools[0].Command)
				assert.Equal(t, []string{"hello", "world"}, tools[0].Args)
			},
		},
		{
			name: "tool with env var resolution",
			config: `{
				"description": "Test tools",
				"tools": [{
					"name": "api_call",
					"description": "Call API",
					"inputSchema": {"type": "object"},
					"command": "curl",
					"args": [{"$env": "TEST_ENDPOINT"}, "-H", "Authorization: Bearer {{.token}}"],
					"env": {
						"API_KEY": {"$env": "TEST_API_KEY"}
					}
				}]
			}`,
			wantError: false,
			validate: func(t *testing.T, cfg Config, tools []ResolvedToolConfig) {
				assert.Len(t, tools, 1)
				assert.Equal(t, "api_call", tools[0].Name)
				assert.Equal(t, []string{"https://api.example.com", "-H", "Authorization: Bearer {{.token}}"}, tools[0].Args)
				assert.Equal(t, "secret-key-123", tools[0].Env["API_KEY"])
			},
		},
		{
			name: "tool with missing env var",
			config: `{
				"description": "Test tools",
				"tools": [{
					"name": "broken",
					"description": "Broken tool",
					"inputSchema": {"type": "object"},
					"command": "echo",
					"args": [{"$env": "MISSING_VAR"}]
				}]
			}`,
			wantError: true,
		},
		{
			name: "tool with user token reference (should fail)",
			config: `{
				"description": "Test tools",
				"tools": [{
					"name": "user_token_tool",
					"description": "Tool with user token",
					"inputSchema": {"type": "object"},
					"command": "echo",
					"args": [{"$userToken": "Bearer {{token}}"}]
				}]
			}`,
			wantError: true,
		},
		{
			name: "multiple tools",
			config: `{
				"description": "Multiple tools",
				"tools": [
					{
						"name": "tool1",
						"description": "First tool",
						"inputSchema": {"type": "object"},
						"command": "echo",
						"args": ["one"]
					},
					{
						"name": "tool2",
						"description": "Second tool",
						"inputSchema": {"type": "object"},
						"command": "echo",
						"args": ["two"],
						"timeout": 30000000000
					}
				]
			}`,
			wantError: false,
			validate: func(t *testing.T, cfg Config, tools []ResolvedToolConfig) {
				assert.Len(t, tools, 2)
				assert.Equal(t, "tool1", tools[0].Name)
				assert.Equal(t, "tool2", tools[1].Name)
				assert.Equal(t, 30*1000*1000*1000, int(tools[1].Timeout)) // 30s in nanoseconds
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawConfig := json.RawMessage(tt.config)
			cfg, tools, err := ResolveConfig(rawConfig)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, cfg, tools)
			}
		})
	}
}

func TestResolveConfig_ComplexEnvVars(t *testing.T) {
	// Set up complex environment
	os.Setenv("DOCKER_IMAGE", "alpine:latest")
	os.Setenv("DOCKER_ARGS", "-v /tmp:/tmp:ro")
	defer os.Unsetenv("DOCKER_IMAGE")
	defer os.Unsetenv("DOCKER_ARGS")

	config := `{
		"description": "Docker tools",
		"tools": [{
			"name": "docker_run",
			"description": "Run docker container",
			"inputSchema": {"type": "object"},
			"command": "docker",
			"args": ["run", "--rm", "-i", {"$env": "DOCKER_ARGS"}, {"$env": "DOCKER_IMAGE"}, "sh", "-c", "{{.command}}"],
			"env": {
				"CONTAINER_NAME": "test-container"
			}
		}]
	}`

	rawConfig := json.RawMessage(config)
	_, tools, err := ResolveConfig(rawConfig)

	require.NoError(t, err)
	assert.Len(t, tools, 1)
	
	tool := tools[0]
	assert.Equal(t, "docker_run", tool.Name)
	assert.Equal(t, []string{"run", "--rm", "-i", "-v /tmp:/tmp:ro", "alpine:latest", "sh", "-c", "{{.command}}"}, tool.Args)
	assert.Equal(t, "test-container", tool.Env["CONTAINER_NAME"])
}