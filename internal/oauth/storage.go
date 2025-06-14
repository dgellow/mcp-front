package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"

	"github.com/dgellow/mcp-front/internal"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// ErrUserTokenNotFound is returned when a user token doesn't exist
var ErrUserTokenNotFound = errors.New("user token not found")

// Ensure Storage implements required interfaces
var _ fosite.Storage = (*Storage)(nil)

// Storage is a simple storage layer - only stores and retrieves data
// It extends the MemoryStore with thread-safe client management
type Storage struct {
	*storage.MemoryStore
	stateCache      sync.Map          // map[string]fosite.AuthorizeRequester
	clientsMutex    sync.RWMutex      // For thread-safe client access
	userTokens      map[string]string // map["email:service"] = token
	userTokensMutex sync.RWMutex
}

// newStorage creates a new storage instance
func newStorage() *Storage {
	return &Storage{
		MemoryStore: storage.NewMemoryStore(),
		userTokens:  make(map[string]string),
	}
}

// generateState creates a cryptographically secure state parameter
func (s *Storage) generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Log the error and return empty string which will fail validation
		internal.LogError("Failed to generate random state: %v", err)
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

// storeAuthorizeRequest stores an authorize request with state
func (s *Storage) storeAuthorizeRequest(state string, req fosite.AuthorizeRequester) {
	s.stateCache.Store(state, req)
}

// getAuthorizeRequest retrieves an authorize request by state (one-time use)
func (s *Storage) getAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool) {
	if req, ok := s.stateCache.Load(state); ok {
		s.stateCache.Delete(state) // One-time use
		return req.(fosite.AuthorizeRequester), true
	}
	return nil, false
}

// GetClient overrides the MemoryStore's GetClient to use our mutex
func (s *Storage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.MemoryStore.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

// createClient creates a dynamic client and stores it thread-safely
func (s *Storage) createClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient {
	// Create as public client (no secret) since MCP Inspector is a public client
	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        nil, // Public client - no secret
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        true, // Mark as public client
	}

	// Thread-safe client storage
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	clientCount := len(s.MemoryStore.Clients)
	s.clientsMutex.Unlock()

	internal.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	internal.Logf("Total clients in storage: %d", clientCount)
	return client
}

// GetAllClients returns all clients thread-safely (for debugging)
func (s *Storage) GetAllClients() map[string]fosite.Client {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	// Create a copy to avoid race conditions
	clients := make(map[string]fosite.Client, len(s.MemoryStore.Clients))
	for id, client := range s.MemoryStore.Clients {
		clients[id] = client
	}
	return clients
}

// GetMemoryStore returns the underlying MemoryStore for fosite
func (s *Storage) GetMemoryStore() *storage.MemoryStore {
	return s.MemoryStore
}

// User token methods

// makeUserTokenKey creates a key for the user token map
func (s *Storage) makeUserTokenKey(userEmail, service string) string {
	return userEmail + ":" + service
}

// GetUserToken retrieves a user's token for a specific service
func (s *Storage) GetUserToken(ctx context.Context, userEmail, service string) (string, error) {
	s.userTokensMutex.RLock()
	defer s.userTokensMutex.RUnlock()

	key := s.makeUserTokenKey(userEmail, service)
	token, exists := s.userTokens[key]
	if !exists {
		return "", ErrUserTokenNotFound
	}
	return token, nil
}

// SetUserToken stores or updates a user's token for a specific service
func (s *Storage) SetUserToken(ctx context.Context, userEmail, service, token string) error {
	s.userTokensMutex.Lock()
	defer s.userTokensMutex.Unlock()

	key := s.makeUserTokenKey(userEmail, service)
	s.userTokens[key] = token
	return nil
}

// DeleteUserToken removes a user's token for a specific service
func (s *Storage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	s.userTokensMutex.Lock()
	defer s.userTokensMutex.Unlock()

	key := s.makeUserTokenKey(userEmail, service)
	delete(s.userTokens, key)
	return nil
}

// ListUserServices returns all services for which a user has configured tokens
func (s *Storage) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	s.userTokensMutex.RLock()
	defer s.userTokensMutex.RUnlock()

	var services []string
	prefix := userEmail + ":"
	for key := range s.userTokens {
		if strings.HasPrefix(key, prefix) {
			service := strings.TrimPrefix(key, prefix)
			services = append(services, service)
		}
	}
	return services, nil
}
