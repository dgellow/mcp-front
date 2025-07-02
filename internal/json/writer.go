package json

import (
	"encoding/json"
	"net/http"

	log "github.com/dgellow/mcp-front/internal/log"
)

// ErrorResponse represents a standard JSON error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// WriteResponse writes a JSON response with the given status code
func WriteResponse(w http.ResponseWriter, statusCode int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.LogError("Failed to encode JSON response: %v", err)
		return err
	}
	return nil
}

// Write writes a JSON response with 200 OK status
func Write(w http.ResponseWriter, data any) error {
	return WriteResponse(w, http.StatusOK, data)
}

// WriteError writes a JSON error response
func WriteError(w http.ResponseWriter, statusCode int, error string, message string) {
	response := ErrorResponse{
		Error:   error,
		Message: message,
	}

	if err := WriteResponse(w, statusCode, response); err != nil {
		// Fallback to plain text error if JSON encoding fails
		http.Error(w, error+": "+message, statusCode)
	}
}

// Common error responses
func WriteUnauthorized(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusUnauthorized, "unauthorized", message)
}

func WriteInternalServerError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusInternalServerError, "internal_server_error", message)
}

func WriteBadRequest(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusBadRequest, "bad_request", message)
}

func WriteNotFound(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusNotFound, "not_found", message)
}

func WriteForbidden(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusForbidden, "forbidden", message)
}

func WriteServiceUnavailable(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusServiceUnavailable, "service_unavailable", message)
}
