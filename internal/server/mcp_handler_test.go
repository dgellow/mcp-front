package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)


// mockUserTokenStore is a testify mock for storage.UserTokenStore
type mockUserTokenStore struct {
	mock.Mock
}

func (m *mockUserTokenStore) GetUserToken(ctx context.Context, userEmail, serverName string) (string, error) {
	args := m.Called(ctx, userEmail, serverName)
	return args.String(0), args.Error(1)
}

func (m *mockUserTokenStore) SetUserToken(ctx context.Context, userEmail, serverName, token string) error {
	args := m.Called(ctx, userEmail, serverName, token)
	return args.Error(0)
}

func (m *mockUserTokenStore) DeleteUserToken(ctx context.Context, userEmail, serverName string) error {
	args := m.Called(ctx, userEmail, serverName)
	return args.Error(0)
}

func (m *mockUserTokenStore) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	args := m.Called(ctx, userEmail)
	return args.Get(0).([]string), args.Error(1)
}

// mockSessionManager is a testify mock for SessionManager
type mockSessionManager struct {
	mock.Mock
}

func (m *mockSessionManager) GetSession(key client.SessionKey) (*client.StdioSession, bool) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*client.StdioSession), args.Bool(1)
}

func (m *mockSessionManager) GetOrCreateSession(ctx context.Context, key client.SessionKey, config *config.MCPClientConfig, info mcp.Implementation, setupBaseURL string) (*client.StdioSession, error) {
	args := m.Called(ctx, key, config, info, setupBaseURL)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.StdioSession), args.Error(1)
}

func (m *mockSessionManager) RemoveSession(key client.SessionKey) {
	m.Called(key)
}

func (m *mockSessionManager) Shutdown() {
	m.Called()
}



// Test helper to create MCPHandler for SSE tests
func createTestMCPHandler(serverName string, config *config.MCPClientConfig) *MCPHandler {
	tokenStore := new(mockUserTokenStore)
	sessionManager := new(mockSessionManager)
	info := mcp.Implementation{Name: "test", Version: "1.0"}
	
	return NewMCPHandler(
		serverName,
		config,
		tokenStore,
		"http://localhost:8080",
		info,
		sessionManager,
		nil,
	)
}


func TestIsMessageRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "message endpoint",
			path:     "/server/message",
			expected: true,
		},
		{
			name:     "message with query",
			path:     "/server/message?sessionId=123",
			expected: true,
		},
		{
			name:     "sse endpoint",
			path:     "/server/sse",
			expected: false,
		},
		{
			name:     "root path",
			path:     "/",
			expected: false,
		},
		{
			name:     "contains message in middle",
			path:     "/server/test/message/other",
			expected: false,
		},
	}

	handler := createTestMCPHandler("test", &config.MCPClientConfig{})
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			result := handler.isMessageRequest(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleMessageRequest_SSEServer(t *testing.T) {
	// Create a mock backend server
	backendCalled := false
	var capturedRequest *http.Request
	var capturedBody []byte
	
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		capturedRequest = r
		capturedBody, _ = io.ReadAll(r.Body)
		
		// Return a JSON-RPC response
		response := jsonrpc.NewResponse(1, map[string]any{"result": "success"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer backendServer.Close()

	// Create handler for SSE server
	sseConfig := &config.MCPClientConfig{
		URL:           backendServer.URL,
		TransportType: config.MCPClientTypeSSE,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		Timeout: 5 * time.Second,
	}
	
	handler := createTestMCPHandler("test-sse", sseConfig)

	// Create test request
	requestBody := jsonrpc.Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test/method",
		Params:  json.RawMessage(`{"key": "value"}`),
	}
	body, _ := json.Marshal(requestBody)
	
	req := httptest.NewRequest(http.MethodPost, "/test-sse/message?sessionId=optional", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Handle request
	handler.handleMessageRequest(context.Background(), rec, req, "user@example.com", sseConfig)

	// Verify backend was called
	assert.True(t, backendCalled, "Backend should have been called")
	
	// Verify request forwarding
	assert.Equal(t, "/message?sessionId=optional", capturedRequest.URL.Path+"?"+capturedRequest.URL.RawQuery)
	assert.Equal(t, "Bearer test-token", capturedRequest.Header.Get("Authorization"))
	assert.Equal(t, "application/json", capturedRequest.Header.Get("Content-Type"))
	assert.Equal(t, body, capturedBody)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "test-value", rec.Header().Get("X-Custom-Header"))
	
	var response jsonrpc.Response
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, float64(1), response.ID)
	
	result, ok := response.Result.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "success", result["result"])
}


func TestForwardMessageToBackend_ErrorCases(t *testing.T) {
	t.Run("backend connection failure", func(t *testing.T) {
		// Use invalid URL to simulate connection failure
		sseConfig := &config.MCPClientConfig{
			URL:           "http://localhost:1", // Port 1 should fail
			TransportType: config.MCPClientTypeSSE,
			Timeout:       100 * time.Millisecond,
		}
		
		handler := createTestMCPHandler("test-sse", sseConfig)

		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "test/method",
		}
		body, _ := json.Marshal(requestBody)
		
		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

		assert.Equal(t, http.StatusOK, rec.Code)
		
		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.NotNil(t, response.Error)
		assert.Equal(t, jsonrpc.InternalError, response.Error.Code)
		assert.Equal(t, "Backend request failed", response.Error.Message)
	})

	t.Run("backend returns error status", func(t *testing.T) {
		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal Server Error"))
		}))
		defer backendServer.Close()

		sseConfig := &config.MCPClientConfig{
			URL:           backendServer.URL,
			TransportType: config.MCPClientTypeSSE,
		}
		
		handler := createTestMCPHandler("test-sse", sseConfig)

		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader([]byte("{}")))
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

		// Should forward the error status
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "Internal Server Error")
	})

	t.Run("invalid request body", func(t *testing.T) {
		handler := createTestMCPHandler("test-sse", &config.MCPClientConfig{})

		// Create a request with a body that fails to read
		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", &failingReader{})
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, &config.MCPClientConfig{})

		assert.Equal(t, http.StatusOK, rec.Code)
		
		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.NotNil(t, response.Error)
		assert.Equal(t, jsonrpc.InternalError, response.Error.Code)
		assert.Equal(t, "Failed to read request", response.Error.Message)
	})
}

func TestForwardMessageToBackend_HeaderHandling(t *testing.T) {
	var capturedHeaders http.Header
	
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header
		w.Header().Set("X-Response-Header", "response-value")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result": "ok"}`))
	}))
	defer backendServer.Close()

	sseConfig := &config.MCPClientConfig{
		URL:           backendServer.URL,
		TransportType: config.MCPClientTypeSSE,
		Headers: map[string]string{
			"Authorization": "Bearer config-token",
			"X-Custom":      "custom-value",
		},
	}
	
	handler := createTestMCPHandler("test-sse", sseConfig)

	req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-Request-Header", "request-value")
	rec := httptest.NewRecorder()

	handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

	// Verify request headers
	assert.Equal(t, "application/json; charset=utf-8", capturedHeaders.Get("Content-Type"))
	assert.Equal(t, "Bearer config-token", capturedHeaders.Get("Authorization"))
	assert.Equal(t, "custom-value", capturedHeaders.Get("X-Custom"))
	// Original request headers should not be forwarded (except Content-Type)
	assert.Empty(t, capturedHeaders.Get("X-Request-Header"))

	// Verify response
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "response-value", rec.Header().Get("X-Response-Header"))
	assert.Equal(t, `{"result": "ok"}`, rec.Body.String())
}

// failingReader simulates a reader that always fails
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("read error")
}