package inline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/dgellow/mcp-front/internal"
)

// Server implements an MCP server from inline configuration
type Server struct {
	name   string
	config Config
	tools  map[string]ResolvedToolConfig
}

// NewServer creates a new inline MCP server
func NewServer(name string, config Config, resolvedTools []ResolvedToolConfig) *Server {
	toolMap := make(map[string]ResolvedToolConfig)
	for _, tool := range resolvedTools {
		toolMap[tool.Name] = tool
	}
	
	return &Server{
		name:   name,
		config: config,
		tools:  toolMap,
	}
}

// Tool represents an MCP tool
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ServerCapabilities represents server capabilities
type ServerCapabilities struct {
	Tools map[string]Tool `json:"tools"`
}

// GetCapabilities returns the server capabilities
func (s *Server) GetCapabilities() ServerCapabilities {
	tools := make(map[string]Tool)
	
	for name, tool := range s.tools {
		var inputSchema map[string]interface{}
		if len(tool.InputSchema) > 0 {
			if err := json.Unmarshal(tool.InputSchema, &inputSchema); err != nil {
				internal.LogError("Failed to unmarshal input schema for tool %s: %v", name, err)
			}
		}
		
		tools[name] = Tool{
			Name:        name,
			Description: tool.Description,
			InputSchema: inputSchema,
		}
	}
	
	return ServerCapabilities{
		Tools: tools,
	}
}

// GetDescription returns the server description
func (s *Server) GetDescription() string {
	return s.config.Description
}

// HandleToolCall executes a tool and returns the result
func (s *Server) HandleToolCall(ctx context.Context, toolName string, args map[string]interface{}) (interface{}, error) {
	tool, exists := s.tools[toolName]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", toolName)
	}
	
	// Process args with template substitution
	processedArgs, err := s.processTemplateArgs(tool.Args, args)
	if err != nil {
		return nil, fmt.Errorf("failed to process arguments: %w", err)
	}
	
	// Set up command
	cmd := exec.CommandContext(ctx, tool.Command, processedArgs...)
	
	// Set environment variables
	for k, v := range tool.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	// Include parent environment
	cmd.Env = append(cmd.Env, os.Environ()...)
	
	// Set timeout if specified
	if tool.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, tool.Timeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, tool.Command, processedArgs...)
	}
	
	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	// Log execution
	internal.LogDebug("Executing inline tool: %s %s", tool.Command, strings.Join(processedArgs, " "))
	
	// Execute
	err = cmd.Run()
	if err != nil {
		internal.LogErrorWithFields("inline", "Tool execution failed", map[string]interface{}{
			"tool":   toolName,
			"error":  err.Error(),
			"stderr": stderr.String(),
		})
		return map[string]interface{}{
			"error":  err.Error(),
			"stderr": stderr.String(),
		}, fmt.Errorf("command failed: %w", err)
	}
	
	// Try to parse as JSON first
	var result interface{}
	if err := json.Unmarshal(stdout.Bytes(), &result); err == nil {
		return result, nil
	}
	
	// Return as text if not JSON
	return map[string]interface{}{
		"output": stdout.String(),
		"stderr": stderr.String(),
	}, nil
}

// processTemplateArgs processes template arguments with the provided args
func (s *Server) processTemplateArgs(templateArgs []string, args map[string]interface{}) ([]string, error) {
	processed := make([]string, 0, len(templateArgs))
	
	for _, arg := range templateArgs {
		// Check if this arg contains templates
		if strings.Contains(arg, "{{") {
			tmpl, err := template.New("arg").Parse(arg)
			if err != nil {
				return nil, fmt.Errorf("failed to parse template: %w", err)
			}
			
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, args); err != nil {
				return nil, fmt.Errorf("failed to execute template: %w", err)
			}
			
			// Only add non-empty results
			result := buf.String()
			if result != "" {
				processed = append(processed, result)
			}
		} else {
			processed = append(processed, arg)
		}
	}
	
	return processed, nil
}