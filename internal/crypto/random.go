package crypto

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/dgellow/mcp-front/internal"
)

// GenerateSecureToken creates a cryptographically secure random token
// Returns a base64 URL-encoded string suitable for use as OAuth state parameters,
// client IDs, CSRF tokens, etc.
func GenerateSecureToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		internal.LogError("Failed to generate random token: %v", err)
		return "" // Returns empty string to fail validation
	}
	return base64.URLEncoding.EncodeToString(b)
}
