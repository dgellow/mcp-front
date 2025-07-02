package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/utils"
	"golang.org/x/crypto/bcrypt"

	"github.com/dgellow/mcp-front/internal/log"
)

// UnmarshalJSON implements custom unmarshaling for MCPClientConfig
func (c *MCPClientConfig) UnmarshalJSON(data []byte) error {
	// Use a raw type to avoid recursion
	type rawConfig struct {
		TransportType     MCPClientType              `json:"transportType,omitempty"`
		Command           json.RawMessage            `json:"command,omitempty"`
		Args              []json.RawMessage          `json:"args,omitempty"`
		Env               map[string]json.RawMessage `json:"env,omitempty"`
		URL               json.RawMessage            `json:"url,omitempty"`
		Headers           map[string]json.RawMessage `json:"headers,omitempty"`
		Timeout           string                     `json:"timeout,omitempty"`
		Options           *Options                   `json:"options,omitempty"`
		RequiresUserToken bool                       `json:"requiresUserToken,omitempty"`
		TokenSetup        *TokenSetupConfig          `json:"tokenSetup,omitempty"`
		ServiceAuths      []ServiceAuth              `json:"serviceAuths,omitempty"`
		InlineConfig      json.RawMessage            `json:"inline,omitempty"`
	}

	var raw rawConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	c.TransportType = raw.TransportType
	c.Options = raw.Options
	c.RequiresUserToken = raw.RequiresUserToken
	c.TokenSetup = raw.TokenSetup
	c.ServiceAuths = raw.ServiceAuths
	c.InlineConfig = raw.InlineConfig

	// Parse timeout if present
	if raw.Timeout != "" {
		timeout, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return fmt.Errorf("parsing timeout: %w", err)
		}
		c.Timeout = timeout
	}

	if c.TransportType == "" {
		return fmt.Errorf("transportType is required")
	}

	// Parse command if present
	if raw.Command != nil {
		parsed, err := ParseConfigValue(raw.Command)
		if err != nil {
			return fmt.Errorf("parsing command: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("command cannot be a user token reference")
		}
		c.Command = parsed.value
	}

	// Parse args if present
	if len(raw.Args) > 0 {
		values, needsToken, err := ParseConfigValueSlice(raw.Args)
		if err != nil {
			return fmt.Errorf("parsing args: %w", err)
		}
		c.Args = values
		c.ArgsNeedToken = needsToken
	}

	// Parse env if present
	if len(raw.Env) > 0 {
		values, needsToken, err := ParseConfigValueMap(raw.Env)
		if err != nil {
			return fmt.Errorf("parsing env: %w", err)
		}
		c.Env = values
		c.EnvNeedsToken = needsToken
	}

	// Parse URL if present
	if raw.URL != nil {
		parsed, err := ParseConfigValue(raw.URL)
		if err != nil {
			return fmt.Errorf("parsing url: %w", err)
		}
		c.URL = parsed.value
		c.URLNeedsToken = parsed.needsUserToken
	}

	// Parse headers if present
	if len(raw.Headers) > 0 {
		values, needsToken, err := ParseConfigValueMap(raw.Headers)
		if err != nil {
			return fmt.Errorf("parsing headers: %w", err)
		}
		c.Headers = values
		c.HeadersNeedToken = needsToken
	}

	// Compile token format regex if present
	if c.TokenSetup != nil && c.TokenSetup.TokenFormat != "" {
		regex, err := regexp.Compile(c.TokenSetup.TokenFormat)
		if err != nil {
			return fmt.Errorf("compiling token format regex: %w", err)
		}
		c.TokenSetup.CompiledRegex = regex
	}

	return nil
}

// UnmarshalJSON implements custom unmarshaling for OAuthAuthConfig
func (o *OAuthAuthConfig) UnmarshalJSON(data []byte) error {
	// Use a raw type to parse references
	type rawOAuth struct {
		Kind                AuthKind        `json:"kind"`
		Issuer              json.RawMessage `json:"issuer"`
		GCPProject          json.RawMessage `json:"gcpProject"`
		AllowedDomains      []string        `json:"allowedDomains"`
		AllowedOrigins      []string        `json:"allowedOrigins"`
		TokenTTL            string          `json:"tokenTtl"`
		Storage             string          `json:"storage"`
		FirestoreDatabase   string          `json:"firestoreDatabase,omitempty"`
		FirestoreCollection string          `json:"firestoreCollection,omitempty"`
		GoogleClientID      json.RawMessage `json:"googleClientId"`
		GoogleClientSecret  json.RawMessage `json:"googleClientSecret"`
		GoogleRedirectURI   json.RawMessage `json:"googleRedirectUri"`
		JWTSecret           json.RawMessage `json:"jwtSecret"`
		EncryptionKey       json.RawMessage `json:"encryptionKey,omitempty"`
	}

	var raw rawOAuth
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Copy simple fields
	o.Kind = raw.Kind
	o.AllowedDomains = raw.AllowedDomains
	o.AllowedOrigins = raw.AllowedOrigins
	o.TokenTTL = raw.TokenTTL
	o.Storage = raw.Storage
	o.FirestoreDatabase = raw.FirestoreDatabase
	o.FirestoreCollection = raw.FirestoreCollection

	// Parse fields that can be references
	fields := []struct {
		name           string
		raw            json.RawMessage
		target         *string
		allowUserToken bool
	}{
		{"issuer", raw.Issuer, &o.Issuer, false},
		{"gcpProject", raw.GCPProject, &o.GCPProject, false},
		{"googleClientId", raw.GoogleClientID, &o.GoogleClientID, false},
		{"googleClientSecret", raw.GoogleClientSecret, &o.GoogleClientSecret, false},
		{"googleRedirectUri", raw.GoogleRedirectURI, &o.GoogleRedirectURI, false},
		{"jwtSecret", raw.JWTSecret, &o.JWTSecret, false},
		{"encryptionKey", raw.EncryptionKey, &o.EncryptionKey, false},
	}

	for _, field := range fields {
		if field.raw == nil {
			continue
		}
		parsed, err := ParseConfigValue(field.raw)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", field.name, err)
		}
		if parsed.needsUserToken && !field.allowUserToken {
			return fmt.Errorf("%s cannot be a user token reference", field.name)
		}
		*field.target = parsed.value
	}

	// Validate JWT secret length
	if len(o.JWTSecret) < 32 {
		return fmt.Errorf("jwt secret must be at least 32 bytes, got %d", len(o.JWTSecret))
	}

	// Validate encryption key if storage requires it
	if o.Storage == "firestore" && o.EncryptionKey == "" {
		return fmt.Errorf("encryption key is required when using firestore storage")
	}
	if o.EncryptionKey != "" && len(o.EncryptionKey) != 32 {
		return fmt.Errorf("encryption key must be exactly 32 bytes, got %d", len(o.EncryptionKey))
	}

	return nil
}

// UnmarshalJSON implements custom unmarshaling for ProxyConfig
func (p *ProxyConfig) UnmarshalJSON(data []byte) error {
	// Use a raw type to parse references
	type rawProxy struct {
		BaseURL  json.RawMessage `json:"baseURL"`
		Addr     json.RawMessage `json:"addr"`
		Name     string          `json:"name"`
		Auth     json.RawMessage `json:"auth"`
		Admin    *AdminConfig    `json:"admin"`
		Sessions *SessionConfig  `json:"sessions"`
	}

	var raw rawProxy
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	p.Name = raw.Name
	p.Admin = raw.Admin
	p.Sessions = raw.Sessions

	// Normalize admin emails for consistent comparison
	if p.Admin != nil && len(p.Admin.AdminEmails) > 0 {
		normalizedEmails := make([]string, len(p.Admin.AdminEmails))
		for i, email := range p.Admin.AdminEmails {
			normalizedEmails[i] = utils.NormalizeEmail(email)
		}
		p.Admin.AdminEmails = normalizedEmails
	}

	// Parse BaseURL
	if raw.BaseURL != nil {
		parsed, err := ParseConfigValue(raw.BaseURL)
		if err != nil {
			return fmt.Errorf("parsing baseURL: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("baseURL cannot be a user token reference")
		}
		p.BaseURL = parsed.value
	}

	// Parse Addr
	if raw.Addr != nil {
		parsed, err := ParseConfigValue(raw.Addr)
		if err != nil {
			return fmt.Errorf("parsing addr: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("addr cannot be a user token reference")
		}
		p.Addr = parsed.value
	}

	// Parse auth based on kind field
	if raw.Auth != nil {
		var authKind struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(raw.Auth, &authKind); err != nil {
			return fmt.Errorf("parsing auth kind: %w", err)
		}

		switch AuthKind(authKind.Kind) {
		case AuthKindOAuth:
			var oauth OAuthAuthConfig
			if err := json.Unmarshal(raw.Auth, &oauth); err != nil {
				return fmt.Errorf("parsing OAuth config: %w", err)
			}
			// Apply defaults for Firestore configuration
			if oauth.Storage == "firestore" {
				if oauth.FirestoreDatabase == "" {
					oauth.FirestoreDatabase = "(default)"
				}
				if oauth.FirestoreCollection == "" {
					oauth.FirestoreCollection = "mcp_front_data"
				}
			}
			p.Auth = &oauth
		default:
			return fmt.Errorf("unknown auth kind: %s (only 'oauth' is supported for proxy auth)", authKind.Kind)
		}
	}

	return nil
}

// ApplyUserToken creates a copy of the config with user tokens substituted
func (c *MCPClientConfig) ApplyUserToken(userToken string) *MCPClientConfig {
	if userToken == "" || !c.RequiresUserToken {
		return c
	}

	result := *c

	// Copy and apply token to env vars
	if c.Env != nil {
		result.Env = make(map[string]string, len(c.Env))
		for key, value := range c.Env {
			if c.EnvNeedsToken != nil && c.EnvNeedsToken[key] {
				result.Env[key] = strings.ReplaceAll(value, "{{token}}", userToken)
			} else {
				result.Env[key] = value
			}
		}
	}

	// Copy and apply token to args
	if c.Args != nil {
		result.Args = make([]string, len(c.Args))
		for i, arg := range c.Args {
			if c.ArgsNeedToken != nil && i < len(c.ArgsNeedToken) && c.ArgsNeedToken[i] {
				result.Args[i] = strings.ReplaceAll(arg, "{{token}}", userToken)
			} else {
				result.Args[i] = arg
			}
		}
	}

	// Apply token to URL if needed
	if c.URLNeedsToken {
		result.URL = strings.ReplaceAll(c.URL, "{{token}}", userToken)
	}

	// Copy and apply token to headers
	if c.Headers != nil {
		result.Headers = make(map[string]string, len(c.Headers))
		for key, value := range c.Headers {
			if c.HeadersNeedToken != nil && c.HeadersNeedToken[key] {
				result.Headers[key] = strings.ReplaceAll(value, "{{token}}", userToken)
			} else {
				result.Headers[key] = value
			}
		}
	}

	// Clear tracking maps (no longer needed after token substitution)
	result.EnvNeedsToken = nil
	result.ArgsNeedToken = nil
	result.URLNeedsToken = false
	result.HeadersNeedToken = nil

	return &result
}

// UnmarshalJSON implements custom unmarshaling for ServiceAuth
func (s *ServiceAuth) UnmarshalJSON(data []byte) error {
	// First unmarshal without custom processing
	type rawServiceAuth struct {
		Type      ServiceAuthType `json:"type"`
		Username  string          `json:"username,omitempty"`
		Password  json.RawMessage `json:"password,omitempty"`
		Tokens    []string        `json:"tokens,omitempty"`
		UserToken json.RawMessage `json:"userToken,omitempty"`
	}

	var raw rawServiceAuth
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	log.LogTraceWithFields("config", "Unmarshaling service auth", map[string]interface{}{
		"type": raw.Type,
	})

	s.Type = raw.Type
	s.Username = raw.Username
	s.Tokens = raw.Tokens

	// Parse password if provided (for basic auth)
	if raw.Password != nil {
		log.LogTraceWithFields("config", "Parsing password for basic auth", map[string]interface{}{
			"username": s.Username,
		})
		parsed, err := ParseConfigValue(raw.Password)
		if err != nil {
			return fmt.Errorf("parsing password: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("password cannot be a user token reference")
		}

		// Hash the password using bcrypt
		log.LogTraceWithFields("config", "Hashing password for basic auth", map[string]interface{}{
			"username": s.Username,
		})
		hashed, err := bcrypt.GenerateFromPassword([]byte(parsed.value), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hashing password: %w", err)
		}
		s.HashedPassword = string(hashed)
	}

	// Parse user token if provided
	if raw.UserToken != nil {
		log.LogTraceWithFields("config", "Parsing user token for service auth", map[string]interface{}{
			"type": s.Type,
		})
		parsed, err := ParseConfigValue(raw.UserToken)
		if err != nil {
			return fmt.Errorf("parsing userToken: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("userToken cannot be a user token reference")
		}
		s.ResolvedUserToken = parsed.value
	}

	// Validate required fields based on type
	switch s.Type {
	case ServiceAuthTypeBasic:
		if s.Username == "" {
			return fmt.Errorf("username is required for basic auth")
		}
		if raw.Password == nil {
			return fmt.Errorf("password is required for basic auth")
		}
	case ServiceAuthTypeBearer:
		if len(s.Tokens) == 0 {
			return fmt.Errorf("at least one token is required for bearer auth")
		}
	default:
		return fmt.Errorf("unknown service auth type: %s", s.Type)
	}

	return nil
}

// UnmarshalJSON implements custom unmarshaling for SessionConfig
func (s *SessionConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Timeout         string `json:"timeout"`
		CleanupInterval string `json:"cleanupInterval"`
		MaxPerUser      *int   `json:"maxPerUser"` // Pointer to detect explicit 0
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Parse timeout if present
	if raw.Timeout != "" {
		timeout, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return fmt.Errorf("parsing timeout: %w", err)
		}
		s.Timeout = timeout
	}

	// Parse cleanupInterval if present
	if raw.CleanupInterval != "" {
		interval, err := time.ParseDuration(raw.CleanupInterval)
		if err != nil {
			return fmt.Errorf("parsing cleanupInterval: %w", err)
		}
		s.CleanupInterval = interval
	}

	// Set MaxPerUser if present (0 is a valid value, means no upper bound)
	if raw.MaxPerUser != nil {
		s.MaxPerUser = *raw.MaxPerUser
	}

	return nil
}
