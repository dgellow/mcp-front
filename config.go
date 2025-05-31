package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

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

// ---- Config Structs ----

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
	LogEnabled     *bool             `json:"logEnabled,omitempty"`
	AuthTokens     []string          `json:"authTokens,omitempty"`
	ToolFilter     *ToolFilterConfig `json:"toolFilter,omitempty"`
}

type MCPProxyConfig struct {
	BaseURL string   `json:"baseURL"`
	Addr    string   `json:"addr"`
	Name    string   `json:"name"`
	Options *Options `json:"options,omitempty"`
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

func parseMCPClientConfig(conf *MCPClientConfig) (any, error) {
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

// ---- OAuth Config ----

type OAuthConfig struct {
	Issuer         string   `json:"issuer"`
	GCPProject     string   `json:"gcp_project"`
	AllowedDomains []string `json:"allowed_domains"`
	TokenTTL       Duration `json:"token_ttl"`
	Storage        string   `json:"storage"` // "memory" or "redis"

	// Google OAuth settings
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"google_client_secret"`
	GoogleRedirectURI  string `json:"google_redirect_uri"`
}

// Duration wraps time.Duration to provide custom JSON marshaling
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration format: %w", err)
	}

	*d = Duration(parsed)
	return nil
}

// MarshalJSON implements json.Marshaler
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// String returns the duration as a string
func (d Duration) String() string {
	return time.Duration(d).String()
}

// ToDuration converts to time.Duration
func (d Duration) ToDuration() time.Duration {
	return time.Duration(d)
}

// Helper functions for optional bools
func boolOrDefault(ptr *bool, defaultValue bool) bool {
	if ptr == nil {
		return defaultValue
	}
	return *ptr
}

func boolPtr(b bool) *bool {
	return &b
}

// ---- Config ----

type Config struct {
	McpProxy   *MCPProxyConfig             `json:"mcpProxy"`
	McpServers map[string]*MCPClientConfig `json:"mcpServers"`
	OAuth      *OAuthConfig                `json:"oauth"`
}

func load(path string) (*Config, error) {
	// Read and parse JSON config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if config.McpProxy == nil {
		return nil, errors.New("mcpProxy is required")
	}
	if config.McpProxy.Options == nil {
		config.McpProxy.Options = &Options{}
	}
	for _, clientConfig := range config.McpServers {
		if clientConfig.Options == nil {
			clientConfig.Options = &Options{}
		}
		if clientConfig.Options.AuthTokens == nil {
			clientConfig.Options.AuthTokens = config.McpProxy.Options.AuthTokens
		}
		if clientConfig.Options.PanicIfInvalid == nil {
			clientConfig.Options.PanicIfInvalid = config.McpProxy.Options.PanicIfInvalid
		}
		if clientConfig.Options.LogEnabled == nil {
			clientConfig.Options.LogEnabled = config.McpProxy.Options.LogEnabled
		}
	}

	// Sanitize configuration values
	SanitizeConfig(&config)

	// Validate configuration
	if err := ValidateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}
