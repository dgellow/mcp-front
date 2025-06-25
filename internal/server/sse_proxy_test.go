package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
)

func TestForwardSSEToBackend(t *testing.T) {
	t.Run("successful SSE proxy", func(t *testing.T) {
		// Create a mock SSE backend
		backendCalled := false
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendCalled = true
			
			// Verify request
			assert.Equal(t, "text/event-stream", r.Header.Get("Accept"))
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			
			// Send SSE response
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Custom-Header", "test-value")
			w.WriteHeader(http.StatusOK)
			
			// Send some SSE data
			_, _ = w.Write([]byte("data: {\"type\":\"test\"}\n\n"))
			w.(http.Flusher).Flush()
		}))
		defer backend.Close()

		// Configure client
		config := &config.MCPClientConfig{
			URL: backend.URL,
			Headers: map[string]string{
				"Authorization": "Bearer test-token",
			},
			Timeout: 5 * time.Second,
		}

		// Create request
		req := httptest.NewRequest(http.MethodGet, "/test/sse", nil)
		rec := httptest.NewRecorder()

		// Call the function
		forwardSSEToBackend(context.Background(), rec, req, config)

		// Verify backend was called
		assert.True(t, backendCalled)
		
		// Verify response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "test-value", rec.Header().Get("X-Custom-Header"))
		assert.Contains(t, rec.Body.String(), "data: {\"type\":\"test\"}")
	})

	t.Run("backend returns non-SSE response", func(t *testing.T) {
		// Create a backend that returns JSON instead of SSE
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error": "not an SSE endpoint"}`))
		}))
		defer backend.Close()

		config := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodGet, "/test/sse", nil)
		rec := httptest.NewRecorder()

		forwardSSEToBackend(context.Background(), rec, req, config)

		// Should return service unavailable
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "Backend is not an SSE server")
	})

	t.Run("backend connection failure", func(t *testing.T) {
		config := &config.MCPClientConfig{
			URL:     "http://localhost:1", // Invalid port
			Timeout: 100 * time.Millisecond,
		}

		req := httptest.NewRequest(http.MethodGet, "/test/sse", nil)
		rec := httptest.NewRecorder()

		forwardSSEToBackend(context.Background(), rec, req, config)

		// Should return service unavailable
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "Backend unavailable")
	})

	t.Run("backend returns error status", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer backend.Close()

		config := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodGet, "/test/sse", nil)
		rec := httptest.NewRecorder()

		forwardSSEToBackend(context.Background(), rec, req, config)

		// Should return service unavailable
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "Backend is not an SSE server")
	})

	t.Run("headers are properly forwarded", func(t *testing.T) {
		var capturedHeaders http.Header
		
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeaders = r.Header
			
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		config := &config.MCPClientConfig{
			URL: backend.URL,
			Headers: map[string]string{
				"Authorization": "Bearer config-token",
				"X-Custom":      "custom-value",
			},
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodGet, "/test/sse", nil)
		req.Header.Set("User-Agent", "test-agent")
		req.Header.Set("X-Request-Header", "request-value")
		rec := httptest.NewRecorder()

		forwardSSEToBackend(context.Background(), rec, req, config)

		// Verify headers were forwarded
		assert.Equal(t, "Bearer config-token", capturedHeaders.Get("Authorization"))
		assert.Equal(t, "custom-value", capturedHeaders.Get("X-Custom"))
		assert.Equal(t, "text/event-stream", capturedHeaders.Get("Accept"))
		
		// Original request headers should also be forwarded (except hop-by-hop)
		assert.Equal(t, "test-agent", capturedHeaders.Get("User-Agent"))
		assert.Equal(t, "request-value", capturedHeaders.Get("X-Request-Header"))
		
		// Hop-by-hop headers should not be forwarded
		assert.Empty(t, capturedHeaders.Get("Connection"))
		assert.Empty(t, capturedHeaders.Get("Upgrade"))
	})

	t.Run("streaming works correctly", func(t *testing.T) {
		messages := []string{
			"data: {\"message\":\"first\"}\n\n",
			"data: {\"message\":\"second\"}\n\n",
			"data: {\"message\":\"third\"}\n\n",
		}
		
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			
			flusher := w.(http.Flusher)
			for _, msg := range messages {
				_, _ = w.Write([]byte(msg))
				flusher.Flush()
			}
		}))
		defer backend.Close()

		config := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodGet, "/test/sse", nil)
		rec := httptest.NewRecorder()

		forwardSSEToBackend(context.Background(), rec, req, config)

		// Verify all messages were streamed
		body := rec.Body.String()
		for _, msg := range messages {
			assert.Contains(t, body, strings.TrimSpace(msg))
		}
	})
}

func TestHandleNonStdioSSERequest(t *testing.T) {
	// Create a mock backend SSE server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"type\":\"endpoint\"}\n\n"))
	}))
	defer backend.Close()

	// Create handler
	config := &config.MCPClientConfig{
		URL:           backend.URL,
		TransportType: config.MCPClientTypeSSE,
		Timeout:       5 * time.Second,
	}
	
	handler := createTestMCPHandler("test-sse", config)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/test-sse/sse", nil)
	rec := httptest.NewRecorder()

	// Handle request
	handler.handleNonStdioSSERequest(context.Background(), rec, req, "user@example.com", config)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "data: {\"type\":\"endpoint\"}")
}

// TestSSEVsStdioRouting verifies that SSE and stdio servers are routed correctly
func TestSSEVsStdioRouting(t *testing.T) {
	t.Run("SSE server uses proxy", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: from-backend\n\n"))
		}))
		defer backend.Close()

		config := &config.MCPClientConfig{
			URL:           backend.URL,
			TransportType: config.MCPClientTypeSSE,
		}
		
		handler := createTestMCPHandler("test-sse", config)
		
		req := httptest.NewRequest(http.MethodGet, "/test-sse/sse", nil)
		rec := httptest.NewRecorder()
		
		handler.ServeHTTP(rec, req)
		
		// Should get response from backend
		assert.Contains(t, rec.Body.String(), "from-backend")
	})

	t.Run("stdio server uses session management", func(t *testing.T) {
		config := &config.MCPClientConfig{
			Command:       "echo",
			Args:          []string{"test"},
			TransportType: config.MCPClientTypeStdio,
		}
		
		handler := createTestMCPHandler("test-stdio", config)
		
		// For stdio, we need a shared SSE server
		handler.sharedSSEServer = &server.SSEServer{}
		
		req := httptest.NewRequest(http.MethodGet, "/test-stdio/sse", nil)
		rec := httptest.NewRecorder()
		
		handler.ServeHTTP(rec, req)
		
		// Should not get the backend response (stdio doesn't proxy)
		assert.NotContains(t, rec.Body.String(), "from-backend")
	})
}