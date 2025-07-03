package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SignedToken provides HMAC-signed JSON tokens with optional expiry
type SignedToken struct {
	signingKey []byte
	ttl        time.Duration
}

// NewSignedToken creates a new signed token handler
func NewSignedToken(signingKey []byte, ttl time.Duration) *SignedToken {
	return &SignedToken{
		signingKey: signingKey,
		ttl:        ttl,
	}
}

// TokenData wraps user data with metadata
type TokenData struct {
	Data      json.RawMessage `json:"data"`
	ExpiresAt time.Time       `json:"expires_at,omitempty"`
}

// Sign marshals data to JSON, signs it with HMAC, and returns a base64-encoded token
func (st *SignedToken) Sign(v any) (string, error) {
	// Marshal user data
	userData, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	// Wrap with metadata
	tokenData := TokenData{
		Data: userData,
	}
	if st.ttl > 0 {
		tokenData.ExpiresAt = time.Now().Add(st.ttl)
	}

	// Marshal complete token
	jsonData, err := json.Marshal(tokenData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token data: %w", err)
	}

	// Create signature
	signature := SignData(string(jsonData), st.signingKey)

	// Combine data and signature
	combined := fmt.Sprintf("%s.%s", base64.URLEncoding.EncodeToString(jsonData), signature)
	return combined, nil
}

// Verify validates the signature, checks expiry, and unmarshals the data
func (st *SignedToken) Verify(token string, v any) error {
	// Split data and signature
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid token format")
	}

	// Decode JSON data
	jsonData, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode token data: %w", err)
	}

	// Verify signature
	signature := parts[1]
	if !ValidateSignedData(string(jsonData), signature, st.signingKey) {
		return fmt.Errorf("invalid signature")
	}

	// Unmarshal token data
	var tokenData TokenData
	if err := json.Unmarshal(jsonData, &tokenData); err != nil {
		return fmt.Errorf("failed to unmarshal token data: %w", err)
	}

	// Check expiry
	if !tokenData.ExpiresAt.IsZero() && time.Now().After(tokenData.ExpiresAt) {
		return fmt.Errorf("token expired")
	}

	// Unmarshal user data
	if err := json.Unmarshal(tokenData.Data, v); err != nil {
		return fmt.Errorf("failed to unmarshal user data: %w", err)
	}

	return nil
}
