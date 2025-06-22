package oauth

import (
	"net/http"

	"github.com/dgellow/mcp-front/internal"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/urlutil"
)

// ProtectedResourceMetadataHandler serves OAuth 2.0 Protected Resource Metadata (RFC 9728)
// This endpoint helps clients discover which authorization servers this resource server trusts
func (s *Server) ProtectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	// Build the metadata response
	metadata := map[string]interface{}{
		"resource": s.config.Issuer, // The canonical URI of this resource server
		"authorization_servers": []string{
			s.config.Issuer, // We are our own authorization server
		},
		"_links": map[string]interface{}{
			"oauth-authorization-server": map[string]string{
				"href": urlutil.MustJoinPath(s.config.Issuer, ".well-known", "oauth-authorization-server"),
			},
		},
	}

	// Write the response
	if err := jsonwriter.Write(w, metadata); err != nil {
		internal.LogErrorWithFields("oauth", "Failed to encode protected resource metadata", map[string]interface{}{
			"error": err.Error(),
		})
	}
}