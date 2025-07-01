package inline

import (
	"encoding/json"
)

// Config represents an inline MCP server configuration
type Config struct {
	Description string       `json:"description"`
	Tools       []ToolConfig `json:"tools"`
}

// ToolConfig represents a single tool in an inline MCP server
type ToolConfig struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	InputSchema json.RawMessage            `json:"inputSchema"`
	Command     string                     `json:"command"`           // Command to run (e.g., "docker", "gcloud", etc.)
	Args        []json.RawMessage          `json:"args,omitempty"`    // Arguments with {"$env": "..."} support
	Env         map[string]json.RawMessage `json:"env,omitempty"`     // Environment variables with {"$env": "..."} support
	Timeout     string                     `json:"timeout,omitempty"` // Timeout for command execution (e.g. "30s")
}

// ResolvedToolConfig represents a tool config with all values resolved
type ResolvedToolConfig struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	InputSchema json.RawMessage   `json:"inputSchema"`
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"` // Resolved arguments
	Env         map[string]string `json:"env,omitempty"`  // Resolved environment variables
	Timeout     string            `json:"timeout,omitempty"`
}
