package json

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteUnauthorizedWithChallenge(t *testing.T) {
	tests := []struct {
		name                string
		message             string
		realm               string
		resourceMetadataURI string
		wantHeader          string
		wantStatus          int
	}{
		{
			name:                "with resource metadata URI and realm",
			message:             "Invalid token",
			realm:               "TestProxy",
			resourceMetadataURI: "https://example.com/.well-known/oauth-protected-resource",
			wantHeader:          `Bearer realm="TestProxy", as_uri="https://example.com/.well-known/oauth-protected-resource"`,
			wantStatus:          http.StatusUnauthorized,
		},
		{
			name:                "without resource metadata URI",
			message:             "Invalid token",
			realm:               "TestProxy",
			resourceMetadataURI: "",
			wantHeader:          "",
			wantStatus:          http.StatusUnauthorized,
		},
		{
			name:                "without realm",
			message:             "Invalid token",
			realm:               "",
			resourceMetadataURI: "https://example.com/.well-known/oauth-protected-resource",
			wantHeader:          "",
			wantStatus:          http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			
			WriteUnauthorizedWithChallenge(w, tt.message, tt.realm, tt.resourceMetadataURI)
			
			if w.Code != tt.wantStatus {
				t.Errorf("status = %v, want %v", w.Code, tt.wantStatus)
			}
			
			gotHeader := w.Header().Get("WWW-Authenticate")
			if gotHeader != tt.wantHeader {
				t.Errorf("WWW-Authenticate header = %q, want %q", gotHeader, tt.wantHeader)
			}
			
			// Check that response contains error message
			body := w.Body.String()
			if body == "" {
				t.Error("expected non-empty response body")
			}
		})
	}
}

func TestWriteUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	
	WriteUnauthorized(w, "Test error")
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %v, want %v", w.Code, http.StatusUnauthorized)
	}
	
	// Should not have WWW-Authenticate header
	if header := w.Header().Get("WWW-Authenticate"); header != "" {
		t.Errorf("unexpected WWW-Authenticate header: %q", header)
	}
}