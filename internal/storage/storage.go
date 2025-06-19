package storage

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	fosite_storage "github.com/ory/fosite/storage"
)

// ErrUserTokenNotFound is returned when a user token doesn't exist
var ErrUserTokenNotFound = errors.New("user token not found")

// ErrUserNotFound is returned when a user doesn't exist
var ErrUserNotFound = errors.New("user not found")

// ErrSessionNotFound is returned when a session doesn't exist
var ErrSessionNotFound = errors.New("session not found")

// UserInfo represents a user who has authenticated via OAuth
type UserInfo struct {
	Email     string    `json:"email"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Enabled   bool      `json:"enabled"`
	IsAdmin   bool      `json:"is_admin"`
}

// ActiveSession represents an active MCP session
type ActiveSession struct {
	SessionID  string    `json:"session_id"`
	UserEmail  string    `json:"user_email"`
	ServerName string    `json:"server_name"`
	Created    time.Time `json:"created"`
	LastActive time.Time `json:"last_active"`
}

// UserTokenStore defines methods for managing user tokens.
// This interface is used by handlers that need to access user-specific tokens
// for external services (e.g., Notion, GitHub).
type UserTokenStore interface {
	GetUserToken(ctx context.Context, userEmail, service string) (string, error)
	SetUserToken(ctx context.Context, userEmail, service, token string) error
	DeleteUserToken(ctx context.Context, userEmail, service string) error
	ListUserServices(ctx context.Context, userEmail string) ([]string, error)
}

// Storage combines all storage capabilities needed by mcp-front
type Storage interface {
	// OAuth storage requirements
	fosite.Storage

	// OAuth state management
	StoreAuthorizeRequest(state string, req fosite.AuthorizeRequester)
	GetAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool)

	// OAuth client management
	CreateClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient
	CreateConfidentialClient(clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient
	GetAllClients() map[string]fosite.Client
	GetMemoryStore() *fosite_storage.MemoryStore

	// User token storage
	UserTokenStore

	// User tracking (upserted when users access MCP endpoints)
	UpsertUser(ctx context.Context, email string) error
	GetAllUsers(ctx context.Context) ([]UserInfo, error)
	UpdateUserStatus(ctx context.Context, email string, enabled bool) error
	DeleteUser(ctx context.Context, email string) error
	SetUserAdmin(ctx context.Context, email string, isAdmin bool) error

	// Session tracking
	TrackSession(ctx context.Context, session ActiveSession) error
	GetActiveSessions(ctx context.Context) ([]ActiveSession, error)
	RevokeSession(ctx context.Context, sessionID string) error
}
