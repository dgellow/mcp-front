package crypto

import (
	"crypto/rand"
	"testing"
)

func TestEncryptor(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty", ""},
		{"short", "hello"},
		{"medium", "this is a test secret that needs encryption"},
		{"long", "secret_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
		{"unicode", "🔐 secret with émojis and spéçial chars"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			// Verify it's base64
			if ciphertext == "" && tt.plaintext != "" {
				t.Error("ciphertext is empty for non-empty plaintext")
			}

			// Decrypt
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			// Verify
			if decrypted != tt.plaintext {
				t.Errorf("got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptorKeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{"too short", 16, true},
		{"correct", 32, false},
		{"too long", 64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := NewEncryptor(key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEncryptor() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptorUniqueness(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	plaintext := "test secret"
	
	// Encrypt same plaintext multiple times
	ciphertext1, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}

	ciphertext2, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}

	// Should produce different ciphertexts due to random nonce
	if ciphertext1 == ciphertext2 {
		t.Error("encrypting same plaintext produced identical ciphertexts")
	}
}

func TestDecryptInvalidInput(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
	}{
		{"invalid base64", "not-base64!@#$"},
		{"too short", "YQ=="}, // just "a" in base64
		{"random valid base64", "dGVzdCBkYXRh"}, // "test data" - not encrypted
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.Decrypt(tt.ciphertext)
			if err == nil {
				t.Error("expected error decrypting invalid ciphertext")
			}
		})
	}
}