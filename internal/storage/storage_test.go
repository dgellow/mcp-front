package storage

import (
	"context"
	"testing"

	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestMemoryStorageConfidentialClient(t *testing.T) {
	storage := NewMemoryStorage()
	
	// Generate test data
	clientID := "test-client-123"
	secret := crypto.GenerateClientSecret()
	hashedSecret, err := crypto.HashClientSecret(secret)
	assert.NoError(t, err)
	
	redirectURIs := []string{"https://example.com/callback"}
	scopes := []string{"read", "write"}
	issuer := "https://issuer.example.com"
	
	// Create confidential client
	client := storage.CreateConfidentialClient(clientID, hashedSecret, redirectURIs, scopes, issuer)
	
	// Verify client properties
	assert.Equal(t, clientID, client.GetID())
	assert.Equal(t, hashedSecret, client.GetHashedSecret())
	assert.Equal(t, redirectURIs, client.GetRedirectURIs())
	assert.ElementsMatch(t, scopes, client.GetScopes())
	assert.ElementsMatch(t, []string{issuer}, client.GetAudience())
	assert.False(t, client.IsPublic(), "Confidential client should not be public")
	
	// Verify client is stored
	ctx := context.Background()
	storedClient, err := storage.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, storedClient)
	assert.Equal(t, clientID, storedClient.GetID())
	assert.False(t, storedClient.IsPublic())
	
	// Verify the stored secret can be used for authentication
	err = bcrypt.CompareHashAndPassword(storedClient.GetHashedSecret(), []byte(secret))
	assert.NoError(t, err, "Original secret should verify against stored hash")
}

func TestMemoryStoragePublicVsConfidential(t *testing.T) {
	storage := NewMemoryStorage()
	
	// Create public client
	publicClient := storage.CreateClient("public-123", []string{"https://public.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.True(t, publicClient.IsPublic())
	assert.Nil(t, publicClient.GetHashedSecret())
	
	// Create confidential client
	hashedSecret := []byte("hashed-secret")
	confidentialClient := storage.CreateConfidentialClient("confidential-123", hashedSecret, []string{"https://confidential.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.False(t, confidentialClient.IsPublic())
	assert.NotNil(t, confidentialClient.GetHashedSecret())
	assert.Equal(t, hashedSecret, confidentialClient.GetHashedSecret())
}