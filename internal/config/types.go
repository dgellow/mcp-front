package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// MCPClientType represents the transport type for MCP clients
type MCPClientType string

const (
	MCPClientTypeStdio      MCPClientType = "stdio"
	MCPClientTypeSSE        MCPClientType = "sse"
	MCPClientTypeStreamable MCPClientType = "streamable-http"
)

// AuthKind represents the type of authentication
type AuthKind string

const (
	AuthKindOAuth       AuthKind = "oauth"
	AuthKindBearerToken AuthKind = "bearerToken"
)

// ToolFilterMode for tool filtering
type ToolFilterMode string

const (
	ToolFilterModeAllow ToolFilterMode = "allow"
	ToolFilterModeBlock ToolFilterMode = "block"
)

// ToolFilterConfig configures tool filtering
type ToolFilterConfig struct {
	Mode ToolFilterMode `json:"mode,omitempty"`
	List []string       `json:"list,omitempty"`
}

// Options for MCP client configuration
type Options struct {
	PanicIfInvalid *bool             `json:"panicIfInvalid,omitempty"`
	AuthTokens     []string          `json:"authTokens,omitempty"`
	ToolFilter     *ToolFilterConfig `json:"toolFilter,omitempty"`
}

// TokenSetupConfig provides information for users to set up their tokens
type TokenSetupConfig struct {
	DisplayName   string         `json:"displayName"`
	Instructions  string         `json:"instructions"`
	HelpURL       string         `json:"helpUrl,omitempty"`
	TokenFormat   string         `json:"tokenFormat,omitempty"`
	CompiledRegex *regexp.Regexp `json:"-"`
}

// BearerTokenAuthConfig represents bearer token authentication
type BearerTokenAuthConfig struct {
	Kind   AuthKind            `json:"kind"`
	Tokens map[string][]string `json:"tokens"` // server name -> tokens
}

// MCPClientConfig represents the configuration for an MCP client after parsing.
//
// Environment variable references using {"$env": "VAR_NAME"} syntax are resolved
// at config load time. This explicit JSON syntax was chosen over bash-like $VAR
// substitution for important security reasons:
//
//  1. Shell Safety: Config files are often manipulated in shell contexts (startup
//     scripts, CI/CD pipelines). Using $VAR could lead to accidental expansion by
//     the shell before the config is parsed.
//
//  2. Unambiguous Intent: {"$env": "X"} clearly indicates this is a reference to
//     be resolved by our application, not a literal string containing $.
//
//  3. Nested Value Safety: If an environment variable value contains $, it won't
//     be accidentally re-expanded.
//
//  4. Type Safety: The JSON structure allows us to validate references at parse
//     time rather than discovering invalid patterns at runtime.
//
// User token references using {"$userToken": "...{{token}}..."} follow the same
// pattern but are resolved at request time with the authenticated user's token.
type MCPClientConfig struct {
	TransportType MCPClientType `json:"transportType,omitempty"`

	// Stdio
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// Track which values need user token substitution
	EnvNeedsToken map[string]bool `json:"-"`
	ArgsNeedToken []bool          `json:"-"`

	// SSE or Streamable HTTP
	URL              string            `json:"url,omitempty"`
	URLNeedsToken    bool              `json:"-"` // Track if URL needs token substitution
	Headers          map[string]string `json:"headers,omitempty"`
	HeadersNeedToken map[string]bool   `json:"-"` // Track which headers need token substitution
	Timeout          time.Duration     `json:"timeout,omitempty"`

	Options *Options `json:"options,omitempty"`

	// User token requirements
	RequiresUserToken bool              `json:"requiresUserToken,omitempty"`
	TokenSetup        *TokenSetupConfig `json:"tokenSetup,omitempty"`
}

// AdminConfig represents admin UI configuration
type AdminConfig struct {
	Enabled     bool     `json:"enabled"`
	AdminEmails []string `json:"adminEmails"`
}

// OAuthAuthConfig represents OAuth 2.1 configuration with resolved values
type OAuthAuthConfig struct {
	Kind                AuthKind `json:"kind"`
	Issuer              string   `json:"issuer"`
	GCPProject          string   `json:"gcpProject"`
	AllowedDomains      []string `json:"allowedDomains"` // For Google OAuth email validation
	AllowedOrigins      []string `json:"allowedOrigins"` // For CORS validation
	TokenTTL            string   `json:"tokenTtl"`
	Storage             string   `json:"storage"`                       // "memory" or "firestore"
	FirestoreDatabase   string   `json:"firestoreDatabase,omitempty"`   // Optional: Firestore database name
	FirestoreCollection string   `json:"firestoreCollection,omitempty"` // Optional: Firestore collection name
	GoogleClientID      string   `json:"googleClientId"`
	GoogleClientSecret  string   `json:"googleClientSecret"`
	GoogleRedirectURI   string   `json:"googleRedirectUri"`
	JWTSecret           string   `json:"jwtSecret"`
	EncryptionKey       string   `json:"encryptionKey"`
}

// ProxyConfig represents the proxy configuration with resolved values
type ProxyConfig struct {
	BaseURL string        `json:"baseURL"`
	Addr    string        `json:"addr"`
	Name    string        `json:"name"`
	Auth    interface{}   `json:"-"` // OAuthAuthConfig or BearerTokenAuthConfig
	Admin   *AdminConfig  `json:"admin,omitempty"`
}

// Config represents the config structure with resolved values
type Config struct {
	Proxy      ProxyConfig                 `json:"proxy"`
	MCPServers map[string]*MCPClientConfig `json:"mcpServers"`
}

// RawConfigValue represents a value that could be a string, env ref, or user token ref
// This is only used during parsing, not in the final config
type RawConfigValue struct {
	value          string
	needsUserToken bool
}

// parseConfigValue parses a JSON value that could be a string or reference object
func parseConfigValue(raw json.RawMessage) (*RawConfigValue, error) {
	// Try plain string first
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return &RawConfigValue{value: str, needsUserToken: false}, nil
	}

	// Try reference object
	var ref map[string]string
	if err := json.Unmarshal(raw, &ref); err != nil {
		return nil, fmt.Errorf("config value must be string or reference object")
	}

	// Check for $env reference
	if envVar, ok := ref["$env"]; ok {
		value := os.Getenv(envVar)
		if value == "" {
			return nil, fmt.Errorf("environment variable %s not set", envVar)
		}
		// Strip surrounding quotes if present (only matching pairs)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		return &RawConfigValue{value: value, needsUserToken: false}, nil
	}

	// Check for $userToken reference
	if template, ok := ref["$userToken"]; ok {
		return &RawConfigValue{value: template, needsUserToken: true}, nil
	}

	return nil, fmt.Errorf("unknown reference type in config value")
}

// parseConfigValueSlice parses a slice that may contain references
func parseConfigValueSlice(raw []json.RawMessage) ([]string, []bool, error) {
	values := make([]string, len(raw))
	needsToken := make([]bool, len(raw))

	for i, item := range raw {
		parsed, err := parseConfigValue(item)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing item %d: %w", i, err)
		}
		values[i] = parsed.value
		needsToken[i] = parsed.needsUserToken
	}

	return values, needsToken, nil
}

// parseConfigValueMap parses a map that may contain references
func parseConfigValueMap(raw map[string]json.RawMessage) (map[string]string, map[string]bool, error) {
	values := make(map[string]string)
	needsToken := make(map[string]bool)

	for key, item := range raw {
		parsed, err := parseConfigValue(item)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing key %s: %w", key, err)
		}
		values[key] = parsed.value
		needsToken[key] = parsed.needsUserToken
	}

	return values, needsToken, nil
}
