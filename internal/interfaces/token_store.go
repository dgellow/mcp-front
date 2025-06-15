package interfaces

import "context"

// UserTokenStore defines methods for managing user tokens.
// This interface is used by handlers that need to access user-specific tokens
// for external services (e.g., Notion, GitHub).
type UserTokenStore interface {
	GetUserToken(ctx context.Context, userEmail, service string) (string, error)
	SetUserToken(ctx context.Context, userEmail, service, token string) error
	DeleteUserToken(ctx context.Context, userEmail, service string) error
	ListUserServices(ctx context.Context, userEmail string) ([]string, error)
}
