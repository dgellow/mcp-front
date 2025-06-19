package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestGenerateClientSecret(t *testing.T) {
	// Test that GenerateClientSecret returns a non-empty string
	secret, err := GenerateClientSecret()
	assert.NoError(t, err, "GenerateClientSecret should not return an error")
	assert.NotEmpty(t, secret, "Client secret should not be empty")

	// Test that each call generates a unique secret
	secret2, err := GenerateClientSecret()
	assert.NoError(t, err)
	assert.NotEqual(t, secret, secret2, "Each client secret should be unique")

	// Test that the secret has reasonable length (base64 encoding of 32 bytes)
	// 32 bytes = 256 bits, base64 encoding adds ~33% overhead
	assert.GreaterOrEqual(t, len(secret), 40, "Client secret should be at least 40 chars")
}

func TestHashClientSecret(t *testing.T) {
	secret := "test-client-secret-12345"

	// Test that hashing works
	hashed, err := HashClientSecret(secret)
	assert.NoError(t, err, "Hashing should not return an error")
	assert.NotNil(t, hashed, "Hashed secret should not be nil")
	assert.NotEmpty(t, hashed, "Hashed secret should not be empty")

	// Test that the hash is different from the original
	assert.NotEqual(t, []byte(secret), hashed, "Hashed secret should differ from original")

	// Test that bcrypt can verify the hash
	err = bcrypt.CompareHashAndPassword(hashed, []byte(secret))
	assert.NoError(t, err, "bcrypt should verify the correct password")

	// Test that bcrypt rejects wrong password
	err = bcrypt.CompareHashAndPassword(hashed, []byte("wrong-password"))
	assert.Error(t, err, "bcrypt should reject wrong password")

	// Test that hashing the same secret twice produces different hashes (due to salt)
	hashed2, err := HashClientSecret(secret)
	assert.NoError(t, err)
	assert.NotEqual(t, hashed, hashed2, "Same secret should produce different hashes due to salt")
}

func TestHashClientSecretIntegration(t *testing.T) {
	// Test the full flow: generate, hash, verify
	secret, err := GenerateClientSecret()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	hashed, err := HashClientSecret(secret)
	assert.NoError(t, err)

	// Verify the generated secret works with the hash
	err = bcrypt.CompareHashAndPassword(hashed, []byte(secret))
	assert.NoError(t, err, "Generated secret should verify against its hash")
}
