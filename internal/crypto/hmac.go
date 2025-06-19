package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// SignData creates an HMAC-SHA256 signature of the data using the provided key
func SignData(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// ValidateSignedData verifies the HMAC-SHA256 signature of the data
func ValidateSignedData(data, signature string, key []byte) bool {
	expectedSig := SignData(data, key)
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}
