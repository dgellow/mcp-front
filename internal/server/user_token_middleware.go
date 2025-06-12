package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/config"
)

// TokenRequiredError is the structured error response for Claude
type TokenRequiredError struct {
	Error         string `json:"error"`
	Service       string `json:"service"`
	SetupURL      string `json:"setup_url"`
	UserMessage   string `json:"user_message"`
	MessageToAI   string `json:"message_to_ai_agent"`
}


// sendTokenRequiredError sends a structured error response for Claude
func sendTokenRequiredError(w http.ResponseWriter, serverName string, serverConfig *config.MCPClientConfig, setupBaseURL string) {
	displayName := serverName
	
	if serverConfig.TokenSetup != nil {
		if serverConfig.TokenSetup.DisplayName != "" {
			displayName = serverConfig.TokenSetup.DisplayName
		}
	}

	errorResp := TokenRequiredError{
		Error:       "user_token_required",
		Service:     serverName,
		SetupURL:    fmt.Sprintf("%s/my/tokens", setupBaseURL),
		UserMessage: fmt.Sprintf("To use %s, please configure your API token at %s/my/tokens", displayName, setupBaseURL),
		MessageToAI: "IMPORTANT: Please relay this message to the user exactly as written, including the URL",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(errorResp); err != nil {
		internal.LogErrorWithFields("token", "Failed to encode error response", map[string]interface{}{
			"error": err.Error(),
		})
	}
}