package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/dgellow/mcp-front/internal"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// OAuthStorage defines the interface for OAuth client storage
type OAuthStorage interface {
	fosite.Storage
	generateState() string
	storeAuthorizeRequest(state string, req fosite.AuthorizeRequester)
	getAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool)
	createClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient
	GetAllClients() map[string]fosite.Client
	GetMemoryStore() *storage.MemoryStore // Expose underlying MemoryStore for fosite
}

// Ensure Storage implements OAuthStorage interface
var _ OAuthStorage = (*Storage)(nil)

// Storage is a simple storage layer - only stores and retrieves data
// It extends the MemoryStore with thread-safe client management
type Storage struct {
	*storage.MemoryStore
	stateCache   sync.Map     // map[string]fosite.AuthorizeRequester
	clientsMutex sync.RWMutex // For thread-safe client access
}

// newStorage creates a new storage instance
func newStorage() *Storage {
	return &Storage{
		MemoryStore: storage.NewMemoryStore(),
	}
}

// generateState creates a cryptographically secure state parameter
func (s *Storage) generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // This should never happen with crypto/rand
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
