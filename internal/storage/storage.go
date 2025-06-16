package storage

import (
	"context"
	"errors"

	"github.com/ory/fosite"
	fosite_storage "github.com/ory/fosite/storage"
)

// ErrUserTokenNotFound is returned when a user token doesn't exist
var ErrUserTokenNotFound = errors.New("user token not found")

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
}
