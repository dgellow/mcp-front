package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

// ValidateConfig validates the entire configuration
func ValidateConfig(config *Config) error {
	var errors ValidationErrors

	// Validate MCP Proxy configuration
	if err := validateMCPProxyConfig(config.McpProxy); err != nil {
		if ve, ok := err.(ValidationErrors); ok {
			errors = append(errors, ve...)
		} else {
			errors = append(errors, ValidationError{Field: "mcpProxy", Message: err.Error()})
		}
	}

	// Validate OAuth configuration if present
	if config.OAuth != nil {
		if err := validateOAuthConfig(config.OAuth); err != nil {
			if ve, ok := err.(ValidationErrors); ok {
				errors = append(errors, ve...)
			} else {
				errors = append(errors, ValidationError{Field: "oauth", Message: err.Error()})
			}
		}
	}

	// Validate MCP servers configuration
	if err := validateMCPServersConfig(config.McpServers); err != nil {
		if ve, ok := err.(ValidationErrors); ok {
			errors = append(errors, ve...)
		} else {
			errors = append(errors, ValidationError{Field: "mcpServers", Message: err.Error()})
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateMCPProxyConfig validates the MCP proxy configuration
func validateMCPProxyConfig(config *MCPProxyConfigV2) error {
	var errors ValidationErrors

	if config == nil {
		return ValidationError{Field: "mcpProxy", Message: "configuration is required"}
	}

	// Validate base URL
	if config.BaseURL == "" {
		errors = append(errors, ValidationError{Field: "mcpProxy.baseURL", Message: "base URL is required"})
	} else {
		if _, err := url.Parse(config.BaseURL); err != nil {
			errors = append(errors, ValidationError{Field: "mcpProxy.baseURL", Message: fmt.Sprintf("invalid URL: %v", err)})
		}
	}

	// Validate address
	if config.Addr == "" {
		errors = append(errors, ValidationError{Field: "mcpProxy.addr", Message: "address is required"})
	} else if !strings.HasPrefix(config.Addr, ":") {
		errors = append(errors, ValidationError{Field: "mcpProxy.addr", Message: "address must start with ':' (e.g., ':8080')"})
	}

	// Validate name
	if config.Name == "" {
		errors = append(errors, ValidationError{Field: "mcpProxy.name", Message: "name is required"})
	}

	// Validate version
	if config.Version == "" {
		errors = append(errors, ValidationError{Field: "mcpProxy.version", Message: "version is required"})
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateOAuthConfig validates the OAuth configuration
func validateOAuthConfig(config *OAuthConfig) error {
	var errors ValidationErrors

	// Validate issuer
	if config.Issuer == "" {
		errors = append(errors, ValidationError{Field: "oauth.issuer", Message: "issuer is required"})
	} else {
		if _, err := url.Parse(config.Issuer); err != nil {
			errors = append(errors, ValidationError{Field: "oauth.issuer", Message: fmt.Sprintf("invalid issuer URL: %v", err)})
		} else if !strings.HasPrefix(config.Issuer, "https://") {
			errors = append(errors, ValidationError{Field: "oauth.issuer", Message: "issuer must use HTTPS in production"})
		}
	}

	// Validate GCP project
	if config.GCPProject == "" {
		errors = append(errors, ValidationError{Field: "oauth.gcp_project", Message: "GCP project ID is required"})
	}

	// Validate allowed domains
	if len(config.AllowedDomains) == 0 {
		errors = append(errors, ValidationError{Field: "oauth.allowed_domains", Message: "at least one allowed domain is required"})
	} else {
		for i, domain := range config.AllowedDomains {
			if domain == "" {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("oauth.allowed_domains[%d]", i), Message: "domain cannot be empty"})
			} else if strings.Contains(domain, "/") || strings.Contains(domain, ":") {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("oauth.allowed_domains[%d]", i), Message: "domain should not contain protocol or path"})
			}
		}
	}

	// Validate token TTL
	ttl := config.TokenTTL.ToDuration()
	if ttl <= 0 {
		errors = append(errors, ValidationError{Field: "oauth.token_ttl", Message: "token TTL must be positive"})
	} else if ttl < 5*time.Minute {
		errors = append(errors, ValidationError{Field: "oauth.token_ttl", Message: "token TTL should be at least 5 minutes"})
	} else if ttl > 24*time.Hour {
		errors = append(errors, ValidationError{Field: "oauth.token_ttl", Message: "token TTL should not exceed 24 hours"})
	}

	// Validate storage type
	if config.Storage != "memory" && config.Storage != "redis" {
		errors = append(errors, ValidationError{Field: "oauth.storage", Message: "storage must be 'memory' or 'redis'"})
	}

	// Validate Google OAuth settings
	if config.GoogleClientID == "" {
		errors = append(errors, ValidationError{Field: "oauth.google_client_id", Message: "Google client ID is required"})
	}

	if config.GoogleClientSecret == "" {
		errors = append(errors, ValidationError{Field: "oauth.google_client_secret", Message: "Google client secret is required"})
	}

	if config.GoogleRedirectURI == "" {
		errors = append(errors, ValidationError{Field: "oauth.google_redirect_uri", Message: "Google redirect URI is required"})
	} else {
		if _, err := url.Parse(config.GoogleRedirectURI); err != nil {
			errors = append(errors, ValidationError{Field: "oauth.google_redirect_uri", Message: fmt.Sprintf("invalid redirect URI: %v", err)})
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateMCPServersConfig validates the MCP servers configuration
func validateMCPServersConfig(servers map[string]*MCPClientConfigV2) error {
	var errors ValidationErrors

	if len(servers) == 0 {
		return ValidationError{Field: "mcpServers", Message: "at least one MCP server is required"}
	}

	for name, config := range servers {
		if name == "" {
			errors = append(errors, ValidationError{Field: "mcpServers", Message: "server name cannot be empty"})
			continue
		}

		// Validate server name format (used in URLs)
		if strings.Contains(name, "/") || strings.Contains(name, " ") {
			errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s", name), Message: "server name cannot contain '/' or spaces"})
		}

		// Validate server configuration
		if err := validateMCPClientConfig(name, config); err != nil {
			if ve, ok := err.(ValidationErrors); ok {
				errors = append(errors, ve...)
			} else {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s", name), Message: err.Error()})
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateMCPClientConfig validates a single MCP client configuration
func validateMCPClientConfig(name string, config *MCPClientConfigV2) error {
	var errors ValidationErrors

	if config == nil {
		return ValidationError{Field: fmt.Sprintf("mcpServers.%s", name), Message: "configuration is required"}
	}

	// Check if it's stdio or HTTP based
	isStdio := config.Command != ""
	isHTTP := config.URL != ""

	if !isStdio && !isHTTP {
		errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s", name), Message: "either 'command' (for stdio) or 'url' (for HTTP) is required"})
	}

	if isStdio && isHTTP {
		errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s", name), Message: "cannot specify both 'command' and 'url'"})
	}

	// Validate stdio configuration
	if isStdio {
		if config.Command == "" {
			errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.command", name), Message: "command is required for stdio transport"})
		}

		// Validate environment variables
		for key, value := range config.Env {
			if key == "" {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.env", name), Message: "environment variable key cannot be empty"})
			}
			if value == "" {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.env.%s", name, key), Message: "environment variable value cannot be empty"})
			}
		}
	}

	// Validate HTTP configuration
	if isHTTP {
		if _, err := url.Parse(config.URL); err != nil {
			errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.url", name), Message: fmt.Sprintf("invalid URL: %v", err)})
		}

		// Validate timeout for streamable HTTP
		if config.TransportType == MCPClientTypeStreamable && config.Timeout <= 0 {
			errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.timeout", name), Message: "timeout is required for streamable HTTP transport"})
		}
	}

	// Validate options
	if config.Options != nil {
		// Validate auth tokens
		for i, token := range config.Options.AuthTokens {
			if token == "" {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.options.authTokens[%d]", name, i), Message: "auth token cannot be empty"})
			}
		}

		// Validate tool filter
		if filter := config.Options.ToolFilter; filter != nil {
			if filter.Mode != ToolFilterModeAllow && filter.Mode != ToolFilterModeBlock {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.options.toolFilter.mode", name), Message: "tool filter mode must be 'allow' or 'block'"})
			}

			if len(filter.List) == 0 {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.options.toolFilter.list", name), Message: "tool filter list cannot be empty when mode is specified"})
			}

			for i, tool := range filter.List {
				if tool == "" {
					errors = append(errors, ValidationError{Field: fmt.Sprintf("mcpServers.%s.options.toolFilter.list[%d]", name, i), Message: "tool name cannot be empty"})
				}
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// SanitizeConfig performs basic sanitization on configuration values
func SanitizeConfig(config *Config) {
	if config.McpProxy != nil {
		// Trim whitespace from strings
		config.McpProxy.BaseURL = strings.TrimSpace(config.McpProxy.BaseURL)
		config.McpProxy.Addr = strings.TrimSpace(config.McpProxy.Addr)
		config.McpProxy.Name = strings.TrimSpace(config.McpProxy.Name)
		config.McpProxy.Version = strings.TrimSpace(config.McpProxy.Version)

		// Ensure baseURL doesn't end with slash
		config.McpProxy.BaseURL = strings.TrimSuffix(config.McpProxy.BaseURL, "/")
	}

	if config.OAuth != nil {
		// Trim whitespace and normalize URLs
		config.OAuth.Issuer = strings.TrimSpace(config.OAuth.Issuer)
		config.OAuth.Issuer = strings.TrimSuffix(config.OAuth.Issuer, "/")
		config.OAuth.GCPProject = strings.TrimSpace(config.OAuth.GCPProject)
		config.OAuth.GoogleClientID = strings.TrimSpace(config.OAuth.GoogleClientID)
		config.OAuth.GoogleClientSecret = strings.TrimSpace(config.OAuth.GoogleClientSecret)
		config.OAuth.GoogleRedirectURI = strings.TrimSpace(config.OAuth.GoogleRedirectURI)

		// Normalize domains (lowercase, trim)
		for i, domain := range config.OAuth.AllowedDomains {
			config.OAuth.AllowedDomains[i] = strings.ToLower(strings.TrimSpace(domain))
		}
	}

	// Sanitize MCP server configurations
	for _, serverConfig := range config.McpServers {
		if serverConfig != nil {
			serverConfig.Command = strings.TrimSpace(serverConfig.Command)
			serverConfig.URL = strings.TrimSpace(serverConfig.URL)

			// Trim args
			for i, arg := range serverConfig.Args {
				serverConfig.Args[i] = strings.TrimSpace(arg)
			}
		}
	}
}