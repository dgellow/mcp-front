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
		
		// For regular parsing (non-user specific), resolve env vars only
		env := make(map[string]string)
		if conf.Env != nil {
			for k, v := range conf.Env {
				if v.IsUserTokenRef() {
					return nil, fmt.Errorf("user token references not allowed in global config for %s", k)
				}
				env[k] = v.String()
			}
		}
		
		args := make([]string, 0, len(conf.Args))
		for i, v := range conf.Args {
			if v.IsUserTokenRef() {
				return nil, fmt.Errorf("user token references not allowed in global config at args[%d]", i)
			}
			args = append(args, v.String())
		}
		
		return &StdioMCPClientConfig{
			Command: conf.Command,
			Env:     env,
			Args:    args,
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
				// Check encryptionKey only if using non-memory storage
				if storage, ok := auth["storage"].(string); ok && storage != "memory" && storage != "" {
					if secret, ok := auth["encryptionKey"]; ok {
						// Check if it's a string (bad) or a map (good - env ref)
						if _, isString := secret.(string); isString {
							return fmt.Errorf("encryptionKey must use environment variable reference for security when using %s storage", storage)
						}
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

	// First parse to check version and validate raw structure
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

	// Parse directly into typed Config struct
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Resolve environment variables in ConfigValue fields
	if config.Proxy.BaseURL != nil {
		if err := config.Proxy.BaseURL.ResolveEnv(); err != nil {
			return nil, fmt.Errorf("resolving proxy.baseURL: %w", err)
		}
	}
	if config.Proxy.Addr != nil {
		if err := config.Proxy.Addr.ResolveEnv(); err != nil {
			return nil, fmt.Errorf("resolving proxy.addr: %w", err)
		}
	}

	// Resolve OAuth config env vars
	if oauth, ok := config.Proxy.Auth.(*OAuthAuthConfig); ok {
		if oauth.Issuer != nil {
			if err := oauth.Issuer.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving oauth.issuer: %w", err)
			}
		}
		if oauth.GCPProject != nil {
			if err := oauth.GCPProject.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving oauth.gcpProject: %w", err)
			}
		}
		if oauth.GoogleClientID != nil {
			if err := oauth.GoogleClientID.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving oauth.googleClientId: %w", err)
			}
		}
		if oauth.GoogleClientSecret != nil {
			if err := oauth.GoogleClientSecret.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving oauth.googleClientSecret: %w", err)
			}
		}
		if oauth.GoogleRedirectURI != nil {
			if err := oauth.GoogleRedirectURI.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving oauth.googleRedirectUri: %w", err)
			}
		}
		if oauth.JWTSecret != nil {
			if err := oauth.JWTSecret.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving oauth.jwtSecret: %w", err)
			}
		}
		if oauth.EncryptionKey != nil {
			if err := oauth.EncryptionKey.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving oauth.encryptionKey: %w", err)
			}
		}
	}

	// Resolve MCP server config env vars (but not user tokens)
	for name, server := range config.MCPServers {
		if server.Env != nil {
			if err := server.Env.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving env for server %s: %w", name, err)
			}
		}
		if server.Args != nil {
			if err := server.Args.ResolveEnv(); err != nil {
				return nil, fmt.Errorf("resolving args for server %s: %w", name, err)
			}
		}
	}


	// Validate config
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
