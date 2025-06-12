package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// Legacy types that are still used in the new config

type StdioMCPClientConfig struct {
	Command string            `json:"command"`
	Env     map[string]string `json:"env"`
	Args    []string          `json:"args"`
}

type SSEMCPClientConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

type StreamableMCPClientConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout time.Duration     `json:"timeout"`
}

type MCPClientType string

const (
	MCPClientTypeStdio      MCPClientType = "stdio"
	MCPClientTypeSSE        MCPClientType = "sse"
	MCPClientTypeStreamable MCPClientType = "streamable-http"
)

type ToolFilterMode string

const (
	ToolFilterModeAllow ToolFilterMode = "allow"
	ToolFilterModeBlock ToolFilterMode = "block"
)

type ToolFilterConfig struct {
	Mode ToolFilterMode `json:"mode,omitempty"`
	List []string       `json:"list,omitempty"`
}

type Options struct {
	PanicIfInvalid *bool             `json:"panicIfInvalid,omitempty"`
	AuthTokens     []string          `json:"authTokens,omitempty"`
	ToolFilter     *ToolFilterConfig `json:"toolFilter,omitempty"`
}

type MCPClientConfig struct {
	TransportType MCPClientType `json:"transportType,omitempty"`

	// Stdio
	Command string           `json:"command,omitempty"`
	Args    ConfigValueSlice `json:"args,omitempty"`
	Env     ConfigValueMap   `json:"env,omitempty"`

	// SSE or Streamable HTTP
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`

	Options *Options `json:"options,omitempty"`

	// User token requirements
	RequiresUserToken bool              `json:"requiresUserToken,omitempty"`
	TokenSetup        *TokenSetupConfig `json:"tokenSetup,omitempty"`
}

// TokenSetupConfig provides information for users to set up their tokens
type TokenSetupConfig struct {
	DisplayName   string         `json:"displayName"`
	Instructions  string         `json:"instructions"`
	HelpURL       string         `json:"helpUrl,omitempty"`
	TokenFormat   string         `json:"tokenFormat,omitempty"`
	CompiledRegex *regexp.Regexp `json:"-"`
}


// AuthKind represents the type of authentication
type AuthKind string

const (
	AuthKindOAuth       AuthKind = "oauth"
	AuthKindBearerToken AuthKind = "bearerToken"
)

// OAuthAuthConfig represents OAuth 2.1 configuration
type OAuthAuthConfig struct {
	Kind                AuthKind      `json:"kind"`
	Issuer              *ConfigValue  `json:"issuer"`
	GCPProject          *ConfigValue  `json:"gcpProject"`
	AllowedDomains      []string      `json:"allowedDomains"`
	TokenTTL            string        `json:"tokenTtl"`
	Storage             string        `json:"storage"`                       // "memory" or "firestore"
	FirestoreDatabase   string        `json:"firestoreDatabase,omitempty"`   // Optional: Firestore database name (default: "(default)")
	FirestoreCollection string        `json:"firestoreCollection,omitempty"` // Optional: Firestore collection name (default: "mcp_front_oauth_clients")
	GoogleClientID      *ConfigValue  `json:"googleClientId"`
	GoogleClientSecret  *ConfigValue  `json:"googleClientSecret"`            // EnvRef only!
	GoogleRedirectURI   *ConfigValue  `json:"googleRedirectUri"`
	JWTSecret           *ConfigValue  `json:"jwtSecret"`                     // EnvRef only!
	EncryptionKey       *ConfigValue  `json:"encryptionKey"`                 // EnvRef only!
}

// BearerTokenAuthConfig represents bearer token authentication
type BearerTokenAuthConfig struct {
	Kind   AuthKind            `json:"kind"`
	Tokens map[string][]string `json:"tokens"` // server name -> tokens
}

// ProxyConfig represents the proxy configuration
type ProxyConfig struct {
	BaseURL *ConfigValue `json:"baseURL"`
	Addr    *ConfigValue `json:"addr"`
	Name    string       `json:"name"`
	Auth    interface{}  `json:"-"` // OAuthAuthConfig or BearerTokenAuthConfig, custom unmarshal
}

// UnmarshalJSON implements custom JSON unmarshaling for ProxyConfig
func (p *ProxyConfig) UnmarshalJSON(data []byte) error {
	// Use an alias to avoid recursion
	type Alias ProxyConfig
	aux := &struct {
		Auth json.RawMessage `json:"auth"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	// Parse auth based on kind field
	if aux.Auth != nil {
		var authKind struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(aux.Auth, &authKind); err != nil {
			return fmt.Errorf("parsing auth kind: %w", err)
		}
		
		switch AuthKind(authKind.Kind) {
		case AuthKindOAuth:
			var oauth OAuthAuthConfig
			if err := json.Unmarshal(aux.Auth, &oauth); err != nil {
				return fmt.Errorf("parsing OAuth config: %w", err)
			}
			p.Auth = &oauth
		case AuthKindBearerToken:
			var bearer BearerTokenAuthConfig
			if err := json.Unmarshal(aux.Auth, &bearer); err != nil {
				return fmt.Errorf("parsing bearer token config: %w", err)
			}
			p.Auth = &bearer
		default:
			return fmt.Errorf("unknown auth kind: %s", authKind.Kind)
		}
	}
	
	return nil
}

// Config represents the new config structure
type Config struct {
	Version    string                      `json:"version"`
	Proxy      ProxyConfig                 `json:"proxy"`
	MCPServers map[string]*MCPClientConfig `json:"mcpServers"`
}

// Helper functions for optional bools
func BoolOrDefault(ptr *bool, defaultValue bool) bool {
	if ptr == nil {
		return defaultValue
	}
	return *ptr
}

func BoolPtr(b bool) *bool {
	return &b
}
