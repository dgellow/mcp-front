package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ParseMCPClientConfig parses MCP client configuration
func ParseMCPClientConfig(conf *MCPClientConfig) (any, error) {
	if conf.Command != "" || conf.TransportType == MCPClientTypeStdio {
		if conf.Command == "" {
			return nil, errors.New("command is required for stdio transport")
		}
		return &StdioMCPClientConfig{
			Command: conf.Command,
			Env:     conf.Env,
			Args:    conf.Args,
		}, nil
	}
	if conf.URL != "" {
		if conf.TransportType == MCPClientTypeStreamable {
			return &StreamableMCPClientConfig{
				URL:     conf.URL,
				Headers: conf.Headers,
				Timeout: conf.Timeout,
			}, nil
		} else {
			return &SSEMCPClientConfig{
				URL:     conf.URL,
				Headers: conf.Headers,
			}, nil
		}
	}
	return nil, errors.New("invalid server type")
}

// resolveEnvRef resolves environment variable references in a value
func resolveEnvRef(value interface{}) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	switch v := value.(type) {
	case map[string]interface{}:
		// Check if this is an EnvRef
		if envName, ok := v["$env"].(string); ok {
			envValue := os.Getenv(envName)
			if envValue == "" {
				if def, hasDefault := v["default"]; hasDefault {
					return def, nil
				}
				return nil, fmt.Errorf("required environment variable %s not set", envName)
			}
			return envValue, nil
		}

		// Otherwise, recursively resolve nested objects
		result := make(map[string]interface{})
		for k, val := range v {
			resolved, err := resolveEnvRef(val)
			if err != nil {
				return nil, fmt.Errorf("resolving %s: %w", k, err)
			}
			result[k] = resolved
		}
		return result, nil

	case []interface{}:
		// Handle arrays
		result := make([]interface{}, len(v))
		for i, item := range v {
			resolved, err := resolveEnvRef(item)
			if err != nil {
				return nil, fmt.Errorf("resolving index %d: %w", i, err)
			}
			result[i] = resolved
		}
		return result, nil

	default:
		// Return primitives as-is
		return value, nil
	}
}

// resolveConfigEnvRefs resolves all environment references in a config struct
func resolveConfigEnvRefs(config interface{}) error {
	// Convert to map for processing
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		return err
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &configMap); err != nil {
		return err
	}

	// Resolve all env refs
	resolved, err := resolveEnvRef(configMap)
	if err != nil {
		return err
	}

	// Convert back to struct
	resolvedBytes, err := json.Marshal(resolved)
	if err != nil {
		return err
	}

	return json.Unmarshal(resolvedBytes, config)
}

// parseAuthConfig parses the auth configuration with proper type discrimination
func parseAuthConfig(authRaw interface{}) (interface{}, error) {
	authMap, ok := authRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("auth must be an object")
	}

	kind, ok := authMap["kind"].(string)
	if !ok {
		return nil, fmt.Errorf("auth.kind is required")
	}

	switch AuthKind(kind) {
	case AuthKindOAuth:
		var oauth OAuthAuthConfig
		jsonBytes, _ := json.Marshal(authMap)
		if err := json.Unmarshal(jsonBytes, &oauth); err != nil {
			return nil, fmt.Errorf("parsing OAuth config: %w", err)
		}
		return &oauth, nil

	case AuthKindBearerToken:
		var bearer BearerTokenAuthConfig
		jsonBytes, _ := json.Marshal(authMap)
		if err := json.Unmarshal(jsonBytes, &bearer); err != nil {
			return nil, fmt.Errorf("parsing bearer token config: %w", err)
		}
		return &bearer, nil

	default:
		return nil, fmt.Errorf("unknown auth kind: %s", kind)
	}
}

// validateRawConfig validates the config structure before environment resolution
func validateRawConfig(rawConfig map[string]interface{}) error {
	// Check if OAuth auth is configured
	if proxy, ok := rawConfig["proxy"].(map[string]interface{}); ok {
		if auth, ok := proxy["auth"].(map[string]interface{}); ok {
			if kind, ok := auth["kind"].(string); ok && kind == "oauth" {
				// Validate that secrets use env refs
				if secret, ok := auth["googleClientSecret"]; ok {
					// Check if it's a string (bad) or a map (good - env ref)
					if _, isString := secret.(string); isString {
						return fmt.Errorf("googleClientSecret must use environment variable reference for security")
					}
				}
				if secret, ok := auth["jwtSecret"]; ok {
					// Check if it's a string (bad) or a map (good - env ref)
					if _, isString := secret.(string); isString {
						return fmt.Errorf("jwtSecret must use environment variable reference for security")
					}
				}
			}
		}
	}
	return nil
}

// Load loads and processes the config format
func Load(path string) (*Config, error) {
	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Parse as raw JSON first to handle env refs
	var rawConfig map[string]interface{}
	if err := json.Unmarshal(data, &rawConfig); err != nil {
		return nil, fmt.Errorf("parsing config JSON: %w", err)
	}

	// Check version
	version, ok := rawConfig["version"].(string)
	if !ok {
		return nil, fmt.Errorf("config version is required")
	}
	if !strings.HasPrefix(version, "v0.0.1-DEV_EDITION") {
		return nil, fmt.Errorf("unsupported config version: %s", version)
	}

	// Validate raw config structure (before env resolution)
	if err := validateRawConfig(rawConfig); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Resolve environment variables
	resolved, err := resolveEnvRef(rawConfig)
	if err != nil {
		return nil, fmt.Errorf("resolving environment variables: %w", err)
	}
	resolvedMap := resolved.(map[string]interface{})

	// Parse into Config
	var config Config
	resolvedBytes, _ := json.Marshal(resolvedMap)
	if err := json.Unmarshal(resolvedBytes, &config); err != nil {
		return nil, fmt.Errorf("parsing resolved config: %w", err)
	}

	// Parse auth config with proper type
	if proxyMap, ok := resolvedMap["proxy"].(map[string]interface{}); ok {
		if authRaw, ok := proxyMap["auth"]; ok {
			auth, err := parseAuthConfig(authRaw)
			if err != nil {
				return nil, fmt.Errorf("parsing auth config: %w", err)
			}
			config.Proxy.Auth = auth
		}
	}

	// Validate config (skip secret validation since we already did it in validateRawConfig)
	if err := ValidateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Process auth tokens for bearer token mode
	if auth, ok := config.Proxy.Auth.(*BearerTokenAuthConfig); ok {
		// Distribute tokens to servers
		for serverName, tokens := range auth.Tokens {
			if server, ok := config.MCPServers[serverName]; ok {
				if server.Options == nil {
					server.Options = &Options{}
				}
				server.Options.AuthTokens = tokens
			}
		}
	}

	return &config, nil
}