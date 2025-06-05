package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal"
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

// ValidateConfig validates the config format
func ValidateConfig(config *Config) error {
	var errors ValidationErrors

	// Validate version
	if config.Version == "" {
		errors = append(errors, ValidationError{Field: "version", Message: "version is required"})
	} else if !strings.HasPrefix(config.Version, "v0.0.1-DEV_EDITION") {
		errors = append(errors, ValidationError{Field: "version", Message: fmt.Sprintf("unsupported version: %s", config.Version)})
	}

	// Validate proxy configuration
	if err := validateProxyConfig(&config.Proxy, config.MCPServers); err != nil {
		if ve, ok := err.(ValidationErrors); ok {
			errors = append(errors, ve...)
		} else {
			errors = append(errors, ValidationError{Field: "proxy", Message: err.Error()})
		}
	}

	// Validate MCP servers
	if err := validateMCPServersConfig(config.MCPServers); err != nil {
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

// validateProxyConfig validates the proxy configuration including auth
func validateProxyConfig(proxy *ProxyConfig, mcpServers map[string]*MCPClientConfig) error {
	var errors ValidationErrors

	// Validate baseURL
	baseURL := fmt.Sprintf("%v", proxy.BaseURL)
	if baseURL == "" || baseURL == "<nil>" {
		errors = append(errors, ValidationError{Field: "proxy.baseURL", Message: "baseURL is required"})
	} else {
		if _, err := url.Parse(baseURL); err != nil {
			errors = append(errors, ValidationError{Field: "proxy.baseURL", Message: fmt.Sprintf("invalid URL: %v", err)})
		}
	}

	// Validate addr
	addr := fmt.Sprintf("%v", proxy.Addr)
	if addr == "" || addr == "<nil>" {
		errors = append(errors, ValidationError{Field: "proxy.addr", Message: "address is required"})
	} else if !strings.HasPrefix(addr, ":") {
		errors = append(errors, ValidationError{Field: "proxy.addr", Message: "address must start with ':' (e.g., ':8080')"})
	}

	// Validate name
	if proxy.Name == "" {
		errors = append(errors, ValidationError{Field: "proxy.name", Message: "name is required"})
	}

	// Validate auth
	if proxy.Auth == nil {
		errors = append(errors, ValidationError{Field: "proxy.auth", Message: "auth configuration is required"})
	} else {
		switch auth := proxy.Auth.(type) {
		case *OAuthAuthConfig:
			if err := validateOAuthAuth(auth); err != nil {
				if ve, ok := err.(ValidationErrors); ok {
					errors = append(errors, ve...)
				} else {
					errors = append(errors, ValidationError{Field: "proxy.auth", Message: err.Error()})
				}
			}

		case *BearerTokenAuthConfig:
			if err := validateBearerTokenAuth(auth, mcpServers); err != nil {
				if ve, ok := err.(ValidationErrors); ok {
					errors = append(errors, ve...)
				} else {
					errors = append(errors, ValidationError{Field: "proxy.auth", Message: err.Error()})
				}
			}

		default:
			errors = append(errors, ValidationError{Field: "proxy.auth", Message: fmt.Sprintf("unknown auth type: %T", auth)})
		}
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateOAuthAuth validates OAuth configuration
func validateOAuthAuth(auth *OAuthAuthConfig) error {
	var errors ValidationErrors

	if auth.Kind != AuthKindOAuth {
		errors = append(errors, ValidationError{Field: "proxy.auth.kind", Message: "must be 'oauth'"})
	}

	// Validate issuer
	issuer := fmt.Sprintf("%v", auth.Issuer)
	if issuer == "" || issuer == "<nil>" {
		errors = append(errors, ValidationError{Field: "proxy.auth.issuer", Message: "issuer is required"})
	} else {
		parsedURL, err := url.Parse(issuer)
		if err != nil {
			errors = append(errors, ValidationError{Field: "proxy.auth.issuer", Message: fmt.Sprintf("invalid issuer URL: %v", err)})
		} else if !strings.HasPrefix(issuer, "https://") {
			// Allow HTTP for localhost development
			if parsedURL.Hostname() != "localhost" && parsedURL.Hostname() != "127.0.0.1" {
				errors = append(errors, ValidationError{Field: "proxy.auth.issuer", Message: "issuer must use HTTPS in production"})
			}
		}
	}

	// Validate GCP project
	gcpProject := fmt.Sprintf("%v", auth.GCPProject)
	if gcpProject == "" || gcpProject == "<nil>" {
		errors = append(errors, ValidationError{Field: "proxy.auth.gcpProject", Message: "GCP project ID is required"})
	}

	// Validate allowed domains
	if len(auth.AllowedDomains) == 0 {
		errors = append(errors, ValidationError{Field: "proxy.auth.allowedDomains", Message: "at least one allowed domain is required"})
	} else {
		for i, domain := range auth.AllowedDomains {
			if domain == "" {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("proxy.auth.allowedDomains[%d]", i), Message: "domain cannot be empty"})
			} else if strings.Contains(domain, "/") || strings.Contains(domain, ":") {
				errors = append(errors, ValidationError{Field: fmt.Sprintf("proxy.auth.allowedDomains[%d]", i), Message: "domain should not contain protocol or path"})
			}
		}
	}

	// Validate token TTL
	if auth.TokenTTL == "" {
		errors = append(errors, ValidationError{Field: "proxy.auth.tokenTtl", Message: "token TTL is required"})
	} else {
		ttl, err := time.ParseDuration(auth.TokenTTL)
		if err != nil {
			errors = append(errors, ValidationError{Field: "proxy.auth.tokenTtl", Message: fmt.Sprintf("invalid duration: %v", err)})
		} else if ttl < 5*time.Minute {
			errors = append(errors, ValidationError{Field: "proxy.auth.tokenTtl", Message: "token TTL should be at least 5 minutes"})
		} else if ttl > 24*time.Hour {
			errors = append(errors, ValidationError{Field: "proxy.auth.tokenTtl", Message: "token TTL should not exceed 24 hours"})
		}
	}

	// Validate storage type
	if auth.Storage != "memory" && auth.Storage != "firestore" {
		errors = append(errors, ValidationError{Field: "proxy.auth.storage", Message: "storage must be 'memory' or 'firestore'"})
	}

	// Validate Google OAuth settings
	clientID := fmt.Sprintf("%v", auth.GoogleClientID)
	if clientID == "" || clientID == "<nil>" {
		errors = append(errors, ValidationError{Field: "proxy.auth.google_client_id", Message: "Google client ID is required"})
	}

	// Client secret validation happens in validateRawConfig before env resolution

	redirectURI := fmt.Sprintf("%v", auth.GoogleRedirectURI)
	if redirectURI == "" || redirectURI == "<nil>" {
		errors = append(errors, ValidationError{Field: "proxy.auth.googleRedirectUri", Message: "Google redirect URI is required"})
	} else {
		if _, err := url.Parse(redirectURI); err != nil {
			errors = append(errors, ValidationError{Field: "proxy.auth.googleRedirectUri", Message: fmt.Sprintf("invalid redirect URI: %v", err)})
		}
	}

	// JWT secret validation happens in validateRawConfig before env resolution

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateBearerTokenAuth validates bearer token configuration
func validateBearerTokenAuth(auth *BearerTokenAuthConfig, mcpServers map[string]*MCPClientConfig) error {
	var errors ValidationErrors
	warnings := []string{}

	if auth.Kind != AuthKindBearerToken {
		errors = append(errors, ValidationError{Field: "proxy.auth.kind", Message: "must be 'bearerToken'"})
	}

	if len(auth.Tokens) == 0 {
		errors = append(errors, ValidationError{Field: "proxy.auth.tokens", Message: "at least one token mapping is required"})
	}

	// Check that all token keys have corresponding servers
	for serverName, tokens := range auth.Tokens {
		if _, exists := mcpServers[serverName]; !exists {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("proxy.auth.tokens.%s", serverName),
				Message: fmt.Sprintf("server '%s' not found in mcpServers", serverName),
			})
		}

		// Validate tokens
		if len(tokens) == 0 {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("proxy.auth.tokens.%s", serverName),
				Message: "at least one token is required",
			})
		}

		for i, token := range tokens {
			if token == "" {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("proxy.auth.tokens.%s[%d]", serverName, i),
					Message: "token cannot be empty",
				})
			}
		}
	}

	// Check that all servers have tokens (warning only)
	for serverName := range mcpServers {
		if _, hasTokens := auth.Tokens[serverName]; !hasTokens {
			warnings = append(warnings, fmt.Sprintf("server '%s' has no tokens configured", serverName))
		}
	}

	// Log warnings
	for _, warning := range warnings {
		internal.Logf("WARNING: %s", warning)
	}

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// validateMCPServersConfig validates the MCP servers configuration
func validateMCPServersConfig(servers map[string]*MCPClientConfig) error {
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
func validateMCPClientConfig(name string, config *MCPClientConfig) error {
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
