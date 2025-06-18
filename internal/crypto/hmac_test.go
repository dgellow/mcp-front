package crypto

import (
	"encoding/base64"
	"testing"
)

func TestSignData(t *testing.T) {
	tests := []struct {
		name string
		data string
		key  []byte
	}{
		{
			name: "basic signing",
			data: "test data",
			key:  []byte("test-key-32-bytes-long-for-hmac!"),
		},
		{
			name: "empty data",
			data: "",
			key:  []byte("test-key-32-bytes-long-for-hmac!"),
		},
		{
			name: "long data",
			data: "this is a much longer piece of data that should still be signed correctly",
			key:  []byte("test-key-32-bytes-long-for-hmac!"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := SignData(tt.data, tt.key)
			
			// Signature should not be empty
			if signature == "" {
				t.Error("SignData returned empty signature")
			}
			
			// Signature should be base64 URL encoded
			if _, err := base64.URLEncoding.DecodeString(signature); err != nil {
				t.Errorf("SignData returned invalid base64 URL encoding: %v", err)
			}
			
			// Same data and key should produce same signature
			signature2 := SignData(tt.data, tt.key)
			if signature != signature2 {
				t.Error("SignData not deterministic")
			}
			
			// Different data should produce different signature
			if tt.data != "" {
				diffSig := SignData(tt.data+"x", tt.key)
				if signature == diffSig {
					t.Error("SignData produced same signature for different data")
				}
			}
		})
	}
}

func TestValidateSignedData(t *testing.T) {
	key := []byte("test-key-32-bytes-long-for-hmac!")
	
	tests := []struct {
		name      string
		data      string
		signature string
		key       []byte
		want      bool
	}{
		{
			name:      "valid signature",
			data:      "test data",
			signature: SignData("test data", key),
			key:       key,
			want:      true,
		},
		{
			name:      "invalid signature",
			data:      "test data",
			signature: "invalid-signature",
			key:       key,
			want:      false,
		},
		{
			name:      "wrong data",
			data:      "test data",
			signature: SignData("different data", key),
			key:       key,
			want:      false,
		},
		{
			name:      "wrong key",
			data:      "test data",
			signature: SignData("test data", key),
			key:       []byte("different-key-32-bytes-long-hmac"),
			want:      false,
		},
		{
			name:      "empty signature",
			data:      "test data",
			signature: "",
			key:       key,
			want:      false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSignedData(tt.data, tt.signature, tt.key)
			if got != tt.want {
				t.Errorf("ValidateSignedData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHMACSecurityProperties(t *testing.T) {
	key1 := []byte("key-1-32-bytes-long-for-hmac-use")
	key2 := []byte("key-2-32-bytes-long-for-hmac-use")
	
	data := "sensitive data"
	
	sig1 := SignData(data, key1)
	sig2 := SignData(data, key2)
	
	// Different keys should produce different signatures
	if sig1 == sig2 {
		t.Error("Different keys produced same signature")
	}
	
	// Signature from key1 should not validate with key2
	if ValidateSignedData(data, sig1, key2) {
		t.Error("Signature validated with wrong key")
	}
	
	// Signature from key2 should not validate with key1
	if ValidateSignedData(data, sig2, key1) {
		t.Error("Signature validated with wrong key")
	}
}