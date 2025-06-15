package oauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFirestoreStorageConfig(t *testing.T) {
	t.Run("missing GCP project ID", func(t *testing.T) {
		// Test that Firestore storage requires GCP project ID
		config := Config{
			Issuer:        "https://test.example.com",
			TokenTTL:      time.Hour,
			JWTSecret:     "test-secret-32-bytes-long-for-testing",
			EncryptionKey: "test-encryption-key-32-bytes-ok!",
			StorageType:   "firestore",
			GCPProjectID:  "", // Missing project ID should fail
		}

		_, err := NewServer(config)
		assert.Error(t, err, "Expected error when GCP project ID is missing for Firestore storage")
		assert.EqualError(t, err, "GCP project ID is required for Firestore storage")
	})

	t.Run("missing encryption key", func(t *testing.T) {
		// Test that Firestore storage requires encryption key
		config := Config{
			Issuer:        "https://test.example.com",
			TokenTTL:      time.Hour,
			JWTSecret:     "test-secret-32-bytes-long-for-testing",
			StorageType:   "firestore",
			GCPProjectID:  "test-project",
			EncryptionKey: "", // Missing encryption key should fail
		}

		_, err := NewServer(config)
		assert.Error(t, err, "Expected error when encryption key is missing for Firestore storage")

		// The error comes from creating the encryptor, not from validation
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key must be 32 bytes", "Expected error about encryption key length")
	})
}

func TestMemoryStorageDefault(t *testing.T) {
	// Test that memory storage works as default
	config := Config{
		Issuer:        "https://test.example.com",
		TokenTTL:      time.Hour,
		JWTSecret:     "test-secret-32-bytes-long-for-testing",
		EncryptionKey: "test-encryption-key-32-bytes-ok!",
		StorageType:   "", // Empty should default to memory
	}

	server, err := NewServer(config)
	assert.NoError(t, err, "Failed to create server with default storage")
	assert.NotNil(t, server, "Expected server to be created")
}

func TestUnsupportedStorageType(t *testing.T) {
	config := Config{
		Issuer:        "https://test.example.com",
		TokenTTL:      time.Hour,
		JWTSecret:     "test-secret-32-bytes-long-for-testing",
		EncryptionKey: "test-encryption-key-32-bytes-ok!",
		StorageType:   "redis", // Unsupported type
	}

	_, err := NewServer(config)
	assert.Error(t, err, "Expected error for unsupported storage type")
	assert.EqualError(t, err, "unsupported storage type: redis")
}
