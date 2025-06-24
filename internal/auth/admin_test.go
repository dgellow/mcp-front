package auth

import (
	"context"
	"testing"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/storage"
)


func TestIsConfigAdmin(t *testing.T) {
	adminConfig := &config.AdminConfig{
		Enabled: true,
		AdminEmails: []string{
			"admin@example.com",
			"ADMIN2@EXAMPLE.COM",
			"  admin3@example.com  ",
		},
	}

	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{
			name:     "exact match lowercase",
			email:    "admin@example.com",
			expected: true,
		},
		{
			name:     "uppercase input for lowercase config",
			email:    "ADMIN@EXAMPLE.COM",
			expected: true,
		},
		{
			name:     "mixed case input",
			email:    "Admin@Example.Com",
			expected: true,
		},
		{
			name:     "exact match uppercase config",
			email:    "admin2@example.com",
			expected: true,
		},
		{
			name:     "whitespace in input",
			email:    "  admin@example.com  ",
			expected: true,
		},
		{
			name:     "match config with whitespace",
			email:    "admin3@example.com",
			expected: true,
		},
		{
			name:     "non-admin email",
			email:    "user@example.com",
			expected: false,
		},
		{
			name:     "empty email",
			email:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsConfigAdmin(tt.email, adminConfig)
			if result != tt.expected {
				t.Errorf("IsConfigAdmin(%q, adminConfig) = %v, want %v", tt.email, result, tt.expected)
			}
		})
	}
}

func TestIsConfigAdmin_NilOrDisabled(t *testing.T) {
	tests := []struct {
		name        string
		adminConfig *config.AdminConfig
		email       string
		expected    bool
	}{
		{
			name:        "nil admin config",
			adminConfig: nil,
			email:       "admin@example.com",
			expected:    false,
		},
		{
			name: "disabled admin config",
			adminConfig: &config.AdminConfig{
				Enabled:     false,
				AdminEmails: []string{"admin@example.com"},
			},
			email:    "admin@example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsConfigAdmin(tt.email, tt.adminConfig)
			if result != tt.expected {
				t.Errorf("IsConfigAdmin(%q, %v) = %v, want %v", tt.email, tt.adminConfig, result, tt.expected)
			}
		})
	}
}

func TestIsAdmin(t *testing.T) {
	ctx := context.Background()
	
	// Create a mock storage with a promoted admin
	store := storage.NewMemoryStorage()
	// Create users and set admin status
	store.UpsertUser(ctx, "PROMOTED@EXAMPLE.COM") // Uppercase to test normalization
	store.SetUserAdmin(ctx, "PROMOTED@EXAMPLE.COM", true)
	store.UpsertUser(ctx, "regular@example.com")
	// regular@example.com remains non-admin by default

	adminConfig := &config.AdminConfig{
		Enabled: true,
		AdminEmails: []string{
			"config-admin@example.com",
		},
	}

	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{
			name:     "config admin with exact case",
			email:    "config-admin@example.com",
			expected: true,
		},
		{
			name:     "config admin with different case",
			email:    "CONFIG-ADMIN@EXAMPLE.COM",
			expected: true,
		},
		{
			name:     "promoted admin with exact case",
			email:    "promoted@example.com",
			expected: true,
		},
		{
			name:     "promoted admin with different case",
			email:    "Promoted@Example.Com",
			expected: true,
		},
		{
			name:     "regular user",
			email:    "regular@example.com",
			expected: false,
		},
		{
			name:     "unknown user",
			email:    "unknown@example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAdmin(ctx, tt.email, adminConfig, store)
			if result != tt.expected {
				t.Errorf("IsAdmin(ctx, %q, adminConfig, store) = %v, want %v", tt.email, result, tt.expected)
			}
		})
	}
}