package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FirestoreStorage implements OAuth client storage using Google Cloud Firestore
type FirestoreStorage struct {
	*storage.MemoryStore
	client          *firestore.Client
	stateCache      sync.Map     // In-memory cache for authorize requests (short-lived)
	clientsMutex    sync.RWMutex // For thread-safe client access
	projectID       string
	collection      string
	encryptor       crypto.Encryptor
	tokenCollection string // Collection for user tokens
}

// Ensure FirestoreStorage implements Storage interface
var _ Storage = (*FirestoreStorage)(nil)
var _ fosite.Storage = (*FirestoreStorage)(nil)

// UserTokenDoc represents a user token document in Firestore
type UserTokenDoc struct {
	UserEmail string    `firestore:"user_email"`
	Service   string    `firestore:"service"`
	Token     string    `firestore:"token"` // Encrypted
	UpdatedAt time.Time `firestore:"updated_at"`
}

// OAuthClientEntity represents the structure stored in Firestore
type OAuthClientEntity struct {
	ID            string   `firestore:"id"`
	Secret        *string  `firestore:"secret,omitempty"` // nil for public clients
	RedirectURIs  []string `firestore:"redirect_uris"`
	Scopes        []string `firestore:"scopes"`
	GrantTypes    []string `firestore:"grant_types"`
	ResponseTypes []string `firestore:"response_types"`
	Audience      []string `firestore:"audience"`
	Public        bool     `firestore:"public"`
	CreatedAt     int64    `firestore:"created_at"`
}

// ToFositeClient converts the Firestore entity to a fosite client
func (e *OAuthClientEntity) ToFositeClient(encryptor crypto.Encryptor) (*fosite.DefaultClient, error) {
	var secret []byte
	if e.Secret != nil {
		// Decrypt the secret
		decrypted, err := encryptor.Decrypt(*e.Secret)
		if err != nil {
			return nil, fmt.Errorf("decrypting client secret: %w", err)
		}
		secret = []byte(decrypted)
	}

	return &fosite.DefaultClient{
		ID:            e.ID,
		Secret:        secret,
		RedirectURIs:  e.RedirectURIs,
		Scopes:        e.Scopes,
		GrantTypes:    e.GrantTypes,
		ResponseTypes: e.ResponseTypes,
		Audience:      e.Audience,
		Public:        e.Public,
	}, nil
}

// FromFositeClient converts a fosite client to a Firestore entity
func FromFositeClient(client fosite.Client, encryptor crypto.Encryptor, createdAt int64) (*OAuthClientEntity, error) {
	var secret *string
	if clientSecret := client.GetHashedSecret(); len(clientSecret) > 0 {
		// Encrypt the secret before storing
		encrypted, err := encryptor.Encrypt(string(clientSecret))
		if err != nil {
			return nil, fmt.Errorf("encrypting client secret: %w", err)
		}
		secret = &encrypted
	}

	return &OAuthClientEntity{
		ID:            client.GetID(),
		Secret:        secret,
		RedirectURIs:  client.GetRedirectURIs(),
		Scopes:        client.GetScopes(),
		GrantTypes:    client.GetGrantTypes(),
		ResponseTypes: client.GetResponseTypes(),
		Audience:      client.GetAudience(),
		Public:        client.IsPublic(),
		CreatedAt:     createdAt,
	}, nil
}

// NewFirestoreStorage creates a new Firestore storage instance
func NewFirestoreStorage(ctx context.Context, projectID, database, collection string, encryptor crypto.Encryptor) (*FirestoreStorage, error) {
	if encryptor == nil {
		return nil, fmt.Errorf("encryptor is required")
	}

	var client *firestore.Client
	var err error

	// Firestore client with custom database
	if database != "" && database != "(default)" {
		client, err = firestore.NewClientWithDatabase(ctx, projectID, database)
	} else {
		client, err = firestore.NewClient(ctx, projectID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Firestore client: %w", err)
	}

	storage := &FirestoreStorage{
		MemoryStore:     storage.NewMemoryStore(),
		client:          client,
		projectID:       projectID,
		collection:      collection,
		encryptor:       encryptor,
		tokenCollection: "mcp_front_user_tokens",
	}

	// Load existing clients from Firestore into memory for fast access
	if err := storage.loadClientsFromFirestore(ctx); err != nil {
		internal.LogError("Failed to load clients from Firestore: %v", err)
		// Don't fail startup, just log the error
	}

	return storage, nil
}

// loadClientsFromFirestore loads all OAuth clients from Firestore into memory
func (s *FirestoreStorage) loadClientsFromFirestore(ctx context.Context) error {
	iter := s.client.Collection(s.collection).Documents(ctx)
	defer iter.Stop()

	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	loadedCount := 0
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("error iterating Firestore documents: %w", err)
		}

		var entity OAuthClientEntity
		if err := doc.DataTo(&entity); err != nil {
			internal.LogError("Failed to unmarshal client from Firestore (client_id: %s): %v", doc.Ref.ID, err)
			continue
		}

		// Store in memory for fast access
		client, err := entity.ToFositeClient(s.encryptor)
		if err != nil {
			internal.LogError("Failed to decrypt client secret (client_id: %s): %v", entity.ID, err)
			continue
		}
		s.MemoryStore.Clients[entity.ID] = client
		loadedCount++
	}

	internal.Logf("Loaded %d OAuth clients from Firestore", loadedCount)
	return nil
}

// StoreAuthorizeRequest stores an authorize request with state (in memory only - short-lived)
func (s *FirestoreStorage) StoreAuthorizeRequest(state string, req fosite.AuthorizeRequester) {
	s.stateCache.Store(state, req)
}

// GetAuthorizeRequest retrieves an authorize request by state (one-time use)
func (s *FirestoreStorage) GetAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool) {
	if req, ok := s.stateCache.Load(state); ok {
		s.stateCache.Delete(state) // One-time use
		return req.(fosite.AuthorizeRequester), true
	}
	return nil, false
}

// GetClient retrieves a client from memory (which is kept in sync with Firestore)
func (s *FirestoreStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.MemoryStore.Clients[id]
	if !ok {
		// Try to load from Firestore if not in memory
		s.clientsMutex.RUnlock()
		client, err := s.loadClientFromFirestore(ctx, id)
		s.clientsMutex.RLock()

		if err != nil {
			return nil, fosite.ErrNotFound
		}
		return client, nil
	}
	return cl, nil
}

// loadClientFromFirestore loads a single client from Firestore
func (s *FirestoreStorage) loadClientFromFirestore(ctx context.Context, clientID string) (fosite.Client, error) {
	doc, err := s.client.Collection(s.collection).Doc(clientID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get client from Firestore: %w", err)
	}

	var entity OAuthClientEntity
	if err := doc.DataTo(&entity); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w", err)
	}

	client, err := entity.ToFositeClient(s.encryptor)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	// Store in memory for future fast access
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	s.clientsMutex.Unlock()

	return client, nil
}

// CreateClient creates a dynamic client and stores it in both memory and Firestore
func (s *FirestoreStorage) CreateClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient {
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

	// Store in Firestore
	ctx := context.Background()
	entity, err := FromFositeClient(client, s.encryptor, time.Now().Unix())
	if err != nil {
		internal.LogError("Failed to encrypt client for Firestore (client_id: %s): %v", clientID, err)
		// Continue with in-memory storage even if encryption fails
	} else {
		_, err := s.client.Collection(s.collection).Doc(clientID).Set(ctx, entity)
		if err != nil {
			internal.LogError("Failed to store client in Firestore (client_id: %s): %v", clientID, err)
			// Continue with in-memory storage even if Firestore fails
		} else {
			internal.Logf("Stored client %s in Firestore", clientID)
		}
	}

	// Thread-safe client storage in memory
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	clientCount := len(s.MemoryStore.Clients)
	s.clientsMutex.Unlock()

	internal.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	internal.Logf("Total clients in storage: %d", clientCount)
	return client
}

// GetAllClients returns all clients thread-safely (for debugging)
func (s *FirestoreStorage) GetAllClients() map[string]fosite.Client {
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
func (s *FirestoreStorage) GetMemoryStore() *storage.MemoryStore {
	return s.MemoryStore
}

// Close closes the Firestore client
func (s *FirestoreStorage) Close() error {
	return s.client.Close()
}

// User token methods

// makeUserTokenDocID creates a document ID for a user token
func (s *FirestoreStorage) makeUserTokenDocID(userEmail, service string) string {
	return userEmail + "__" + service
}

// GetUserToken retrieves a user's token for a specific service
func (s *FirestoreStorage) GetUserToken(ctx context.Context, userEmail, service string) (string, error) {
	docID := s.makeUserTokenDocID(userEmail, service)
	doc, err := s.client.Collection(s.tokenCollection).Doc(docID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return "", ErrUserTokenNotFound
		}
		return "", fmt.Errorf("failed to get token from Firestore: %w", err)
	}

	var tokenDoc UserTokenDoc
	if err := doc.DataTo(&tokenDoc); err != nil {
		return "", fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Decrypt the token
	decrypted, err := s.encryptor.Decrypt(tokenDoc.Token)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token: %w", err)
	}

	return decrypted, nil
}

// SetUserToken stores or updates a user's token for a specific service
func (s *FirestoreStorage) SetUserToken(ctx context.Context, userEmail, service, token string) error {
	// Encrypt the token before storing
	encrypted, err := s.encryptor.Encrypt(token)
	if err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
	}

	docID := s.makeUserTokenDocID(userEmail, service)
	tokenDoc := UserTokenDoc{
		UserEmail: userEmail,
		Service:   service,
		Token:     encrypted,
		UpdatedAt: time.Now(),
	}

	_, err = s.client.Collection(s.tokenCollection).Doc(docID).Set(ctx, tokenDoc)
	if err != nil {
		return fmt.Errorf("failed to store token in Firestore: %w", err)
	}

	return nil
}

// DeleteUserToken removes a user's token for a specific service
func (s *FirestoreStorage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	docID := s.makeUserTokenDocID(userEmail, service)
	_, err := s.client.Collection(s.tokenCollection).Doc(docID).Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete token from Firestore: %w", err)
	}
	return nil
}

// ListUserServices returns all services for which a user has configured tokens
func (s *FirestoreStorage) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	iter := s.client.Collection(s.tokenCollection).Where("user_email", "==", userEmail).Documents(ctx)
	defer iter.Stop()

	var services []string
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate user tokens: %w", err)
		}

		var tokenDoc UserTokenDoc
		if err := doc.DataTo(&tokenDoc); err != nil {
			// Log error but continue with other tokens
			internal.LogError("Failed to unmarshal user token: %v", err)
			continue
		}

		services = append(services, tokenDoc.Service)
	}

	return services, nil
}
