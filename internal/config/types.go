package config

import (
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
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// SSE or Streamable HTTP
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`

	Options *Options `json:"options,omitempty"`
}

// EnvRef represents an environment variable reference in config
type EnvRef struct {
	Env     string      `json:"$env"`
	Default interface{} `json:"default,omitempty"`
}

// AuthKind represents the type of authentication
type AuthKind string

const (
	AuthKindOAuth       AuthKind = "oauth"
	AuthKindBearerToken AuthKind = "bearerToken"
)

// OAuthAuthConfig represents OAuth 2.1 configuration
type OAuthAuthConfig struct {
	Kind                AuthKind    `json:"kind"`
	Issuer              interface{} `json:"issuer"`     // string or EnvRef
	GCPProject          interface{} `json:"gcpProject"` // string or EnvRef
	AllowedDomains      []string    `json:"allowedDomains"`
	TokenTTL            string      `json:"tokenTtl"`
	Storage             string      `json:"storage"`                       // "memory" or "firestore"
	FirestoreDatabase   string      `json:"firestoreDatabase,omitempty"`   // Optional: Firestore database name (default: "(default)")
	FirestoreCollection string      `json:"firestoreCollection,omitempty"` // Optional: Firestore collection name (default: "mcp_front_oauth_clients")
	GoogleClientID      interface{} `json:"googleClientId"`                // string or EnvRef
	GoogleClientSecret  interface{} `json:"googleClientSecret"`            // EnvRef only!
	GoogleRedirectURI   interface{} `json:"googleRedirectUri"`             // string or EnvRef
	JWTSecret           interface{} `json:"jwtSecret"`                     // EnvRef only!
}

// BearerTokenAuthConfig represents bearer token authentication
type BearerTokenAuthConfig struct {
	Kind   AuthKind            `json:"kind"`
	Tokens map[string][]string `json:"tokens"` // server name -> tokens
}

// ProxyConfig represents the proxy configuration
type ProxyConfig struct {
	BaseURL interface{} `json:"baseURL"` // string or EnvRef
	Addr    interface{} `json:"addr"`    // string or EnvRef
	Name    string      `json:"name"`
	Auth    interface{} `json:"auth"` // OAuthAuthConfig or BearerTokenAuthConfig
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
