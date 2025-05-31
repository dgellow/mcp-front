package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// oauthStorage is a simple storage layer - only stores and retrieves data
// It extends the MemoryStore with thread-safe client management
type oauthStorage struct {
	*storage.MemoryStore
	stateCache   sync.Map // map[string]fosite.AuthorizeRequester
	clientsMutex sync.RWMutex // For thread-safe client access
}

// newOAuthStorage creates a new storage instance
func newOAuthStorage() *oauthStorage {
	return &oauthStorage{
		MemoryStore: storage.NewMemoryStore(),
	}
}

// generateState creates a cryptographically secure state parameter
func (s *oauthStorage) generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// storeAuthorizeRequest stores an authorize request with state
func (s *oauthStorage) storeAuthorizeRequest(state string, req fosite.AuthorizeRequester) {
	s.stateCache.Store(state, req)
}

// getAuthorizeRequest retrieves an authorize request by state (one-time use)
func (s *oauthStorage) getAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool) {
	if req, ok := s.stateCache.Load(state); ok {
		s.stateCache.Delete(state) // One-time use
		return req.(fosite.AuthorizeRequester), true
	}
	return nil, false
}

// GetClient overrides the MemoryStore's GetClient to use our mutex
func (s *oauthStorage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.MemoryStore.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

// createClient creates a dynamic client and stores it thread-safely
func (s *oauthStorage) createClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient {
	secret := make([]byte, 32)
	rand.Read(secret)

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        secret,
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
	}

	// Thread-safe client storage
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	clientCount := len(s.MemoryStore.Clients)
	s.clientsMutex.Unlock()

	logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	logf("Total clients in storage: %d", clientCount)
	return client
}

// GetAllClients returns all clients thread-safely (for debugging)
func (s *oauthStorage) GetAllClients() map[string]fosite.Client {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	// Create a copy to avoid race conditions
	clients := make(map[string]fosite.Client, len(s.MemoryStore.Clients))
	for id, client := range s.MemoryStore.Clients {
		clients[id] = client
	}
	return clients
}