package oauth

import (
	"testing"
	"time"
)

func TestFirestoreStorageConfig(t *testing.T) {
	// Test that Firestore storage requires GCP project ID
	config := Config{
		Issuer:       "https://test.example.com",
		TokenTTL:     time.Hour,
		JWTSecret:    "test-secret-32-bytes-long-for-testing",
		StorageType:  "firestore",
		GCPProjectID: "", // Missing project ID should fail
	}

	_, err := NewServer(config)
	if err == nil {
		t.Fatal("Expected error when GCP project ID is missing for Firestore storage")
	}

	if err.Error() != "GCP project ID is required for Firestore storage" {
		t.Fatalf("Expected specific error message, got: %v", err)
	}
}

func TestMemoryStorageDefault(t *testing.T) {
	// Test that memory storage works as default
	config := Config{
		Issuer:      "https://test.example.com",
		TokenTTL:    time.Hour,
		JWTSecret:   "test-secret-32-bytes-long-for-testing",
		StorageType: "", // Empty should default to memory
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server with default storage: %v", err)
	}

	if server == nil {
		t.Fatal("Expected server to be created")
	}
}

func TestUnsupportedStorageType(t *testing.T) {
	config := Config{
		Issuer:      "https://test.example.com",
		TokenTTL:    time.Hour,
		JWTSecret:   "test-secret-32-bytes-long-for-testing",
		StorageType: "redis", // Unsupported type
	}

	_, err := NewServer(config)
	if err == nil {
		t.Fatal("Expected error for unsupported storage type")
	}

	if err.Error() != "unsupported storage type: redis" {
		t.Fatalf("Expected specific error message, got: %v", err)
	}
}