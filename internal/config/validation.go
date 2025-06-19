package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ValidationResult holds validation errors and warnings
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

// ValidationError represents a validation issue
type ValidationError struct {
	Path    string
	Message string
}

// IsValid returns true if there are no errors
func (v *ValidationResult) IsValid() bool {
	return len(v.Errors) == 0
}

// ValidateFile validates a config file structure without requiring env vars
func ValidateFile(path string) (*ValidationResult, error) {
	result := &ValidationResult{}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Check JSON syntax
	var rawConfig map[string]interface{}
	if err := json.Unmarshal(data, &rawConfig); err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Message: fmt.Sprintf("invalid JSON: %v", err),
		})
		return result, nil
	}

	// Check for bash-style syntax
	checkBashStyleSyntax(rawConfig, "", result)

	// Check version
	version, ok := rawConfig["version"].(string)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "version",
			Message: "version field is required",
		})
	} else if !strings.HasPrefix(version, "v0.0.1-DEV_EDITION") {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "version",
			Message: fmt.Sprintf("unsupported version: %s", version),
		})
	}

	// Check proxy structure
	validateProxyStructure(rawConfig, result)

	// Check servers structure
	validateServersStructure(rawConfig, result)

	return result, nil
}

// validateProxyStructure checks the proxy configuration structure
func validateProxyStructure(rawConfig map[string]interface{}, result *ValidationResult) {
	proxy, ok := rawConfig["proxy"].(map[string]interface{})
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy",
			Message: "proxy field is required and must be an object",
		})
		return
	}

	// Check required proxy fields
	if _, ok := proxy["baseURL"]; !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.baseURL",
			Message: "baseURL is required",
		})
	}
	if _, ok := proxy["addr"]; !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.addr",
			Message: "addr is required",
		})
	}

	// Check auth if present
	if auth, ok := proxy["auth"].(map[string]interface{}); ok {
		validateAuthStructure(auth, result)
	}

	// Check admin if present
	if admin, ok := proxy["admin"].(map[string]interface{}); ok {
		validateAdminStructure(admin, result)

		// If admin is enabled, ensure OAuth is configured
		if enabled, ok := admin["enabled"].(bool); ok && enabled {
			hasOAuth := false
			if auth, ok := proxy["auth"].(map[string]interface{}); ok {
				if kind, ok := auth["kind"].(string); ok && kind == "oauth" {
					hasOAuth = true
				}
			}
			if !hasOAuth {
				result.Errors = append(result.Errors, ValidationError{
					Path:    "proxy.admin",
					Message: "admin UI requires OAuth authentication to be configured. Set proxy.auth.kind to 'oauth'",
				})
			}
		}
	}
}

// validateAuthStructure checks auth configuration structure
func validateAuthStructure(auth map[string]interface{}, result *ValidationResult) {
	kind, ok := auth["kind"].(string)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.kind",
			Message: "auth kind is required",
		})
		return
	}

	switch kind {
	case "oauth":
		// Check required OAuth fields
		requiredFields := []struct {
			name string
			hint string
		}{
			{"issuer", ""},
			{"googleClientId", ""},
			{"googleClientSecret", ""},
			{"googleRedirectUri", ""},
			{"jwtSecret", "Hint: Must be at least 32 bytes long for HMAC-SHA256"},
			{"encryptionKey", "Hint: Must be exactly 32 bytes for AES-256-GCM encryption"},
		}
		for _, field := range requiredFields {
			if _, ok := auth[field.name]; !ok {
				msg := fmt.Sprintf("%s is required for OAuth", field.name)
				if field.hint != "" {
					msg += ". " + field.hint
				}
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("proxy.auth.%s", field.name),
					Message: msg,
				})
			}
		}
		if domains, ok := auth["allowedDomains"].([]interface{}); !ok || len(domains) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.auth.allowedDomains",
				Message: "at least one allowed domain is required for OAuth",
			})
		}
		if origins, ok := auth["allowedOrigins"].([]interface{}); !ok || len(origins) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.auth.allowedOrigins",
				Message: "at least one allowed origin is required for OAuth (CORS configuration)",
			})
		}
	case "bearerToken":
		if _, ok := auth["tokens"].(map[string]interface{}); !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.auth.tokens",
				Message: "tokens map is required for bearer token auth",
			})
		}
	default:
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.kind",
			Message: fmt.Sprintf("unknown auth kind: %s", kind),
		})
	}
}

// validateAdminStructure checks admin configuration structure
func validateAdminStructure(admin map[string]interface{}, result *ValidationResult) {
	enabled, ok := admin["enabled"].(bool)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.admin.enabled",
			Message: "enabled field is required and must be a boolean",
		})
		return
	}

	if enabled {
		// Check adminEmails when enabled
		emails, ok := admin["adminEmails"].([]interface{})
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.admin.adminEmails",
				Message: "adminEmails is required when admin is enabled",
			})
		} else if len(emails) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.admin.adminEmails",
				Message: "at least one admin email is required when admin is enabled",
			})
		} else {
			// Validate each email is a string
			for i, email := range emails {
				if _, ok := email.(string); !ok {
					result.Errors = append(result.Errors, ValidationError{
						Path:    fmt.Sprintf("proxy.admin.adminEmails[%d]", i),
						Message: "admin email must be a string",
					})
				}
			}
		}

		// Check that OAuth is configured (required for admin functionality)
		// Note: We check this at the parent level since auth is a sibling of admin
	}
}

// validateServersStructure checks MCP servers configuration
func validateServersStructure(rawConfig map[string]interface{}, result *ValidationResult) {
	servers, ok := rawConfig["mcpServers"].(map[string]interface{})
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "mcpServers",
			Message: "mcpServers field is required and must be an object",
		})
		return
	}

	hasOAuth := false
	if proxy, ok := rawConfig["proxy"].(map[string]interface{}); ok {
		if auth, ok := proxy["auth"].(map[string]interface{}); ok {
			if kind, ok := auth["kind"].(string); ok && kind == "oauth" {
				hasOAuth = true
			}
		}
	}

	for name, server := range servers {
		srv, ok := server.(map[string]interface{})
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s", name),
				Message: "server must be an object",
			})
			continue
		}

		// Check transport type
		transportType, ok := srv["transportType"].(string)
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s.transportType", name),
				Message: "transportType is required",
			})
			continue
		}

		// Validate based on transport type
		switch transportType {
		case "stdio":
			if _, ok := srv["command"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.command", name),
					Message: "command is required for stdio transport",
				})
			}
		case "sse", "streamable-http":
			if _, ok := srv["url"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.url", name),
					Message: fmt.Sprintf("url is required for %s transport", transportType),
				})
			}
		case "inline":
			if _, ok := srv["inline"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.inline", name),
					Message: "inline configuration is required for inline transport",
				})
			}
		default:
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s.transportType", name),
				Message: fmt.Sprintf("invalid transportType: %s", transportType),
			})
		}

		// Check user token requirements
		if requiresToken, ok := srv["requiresUserToken"].(bool); ok && requiresToken {
			if !hasOAuth {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.requiresUserToken", name),
					Message: "server requires user token but OAuth is not configured. Hint: User tokens require OAuth authentication - set proxy.auth.kind to 'oauth'",
				})
			}
			if _, ok := srv["tokenSetup"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.tokenSetup", name),
					Message: "tokenSetup is required when requiresUserToken is true. Hint: Add tokenSetup with displayName and instructions for users to obtain their token",
				})
			}
		}
	}
}

// checkBashStyleSyntax recursively checks for bash-style env var syntax
func checkBashStyleSyntax(value interface{}, path string, result *ValidationResult) {
	bashStyleRegex := regexp.MustCompile(`\$\{?[A-Z_][A-Z0-9_]*\}?`)

	switch v := value.(type) {
	case string:
		if matches := bashStyleRegex.FindAllString(v, -1); len(matches) > 0 {
			for _, match := range matches {
				varName := strings.Trim(match, "${}")
				result.Warnings = append(result.Warnings, ValidationError{
					Path:    path,
					Message: fmt.Sprintf("found bash-style syntax '%s' - use {\"$env\": \"%s\"} instead. Hint: JSON syntax prevents accidental shell expansion in scripts/CI and ensures unambiguous parsing", match, varName),
				})
			}
		}
	case map[string]interface{}:
		// Skip if this is already an env/userToken ref
		if _, hasEnv := v["$env"]; hasEnv {
			return
		}
		if _, hasUserToken := v["$userToken"]; hasUserToken {
			return
		}

		for key, val := range v {
			newPath := path
			if newPath == "" {
				newPath = key
			} else {
				newPath = path + "." + key
			}
			checkBashStyleSyntax(val, newPath, result)
		}
	case []interface{}:
		for i, item := range v {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			checkBashStyleSyntax(item, newPath, result)
		}
	}
}
