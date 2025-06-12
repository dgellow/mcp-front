package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserTokenGetter mocks UserTokenGetter interface
type MockUserTokenGetter struct {
	mock.Mock
}

func (m *MockUserTokenGetter) GetUserToken(ctx context.Context, userEmail, serviceName string) (string, error) {
	args := m.Called(ctx, userEmail, serviceName)
	return args.String(0), args.Error(1)
}

// MockUserMCPManager mocks UserMCPManager interface
type MockUserMCPManager struct {
	mock.Mock
}

func (m *MockUserMCPManager) CreateStdioInstance(ctx context.Context, user, serverName string, config *config.MCPClientConfig, userToken string) (*client.Client, error) {
	args := m.Called(ctx, user, serverName, config, userToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.Client), args.Error(1)
}


func (m *MockUserMCPManager) GetOrCreateSSEServer(ctx context.Context, user, serverName string, config *config.MCPClientConfig, userToken string, info mcp.Implementation, setupBaseURL string) (*client.Server, error) {
	args := m.Called(ctx, user, serverName, config, userToken, info, setupBaseURL)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.Server), args.Error(1)
}

func TestMCPHandler_ServeHTTP_NoUserInContext(t *testing.T) {
	cfg := &config.MCPClientConfig{
		RequiresUserToken: false,
	}

	mockServerFunc := func(name, version, baseURL string, config *config.MCPClientConfig) *client.Server {
		t.Fatal("Should not create server when no user in context")
		return nil
	}

	handler := newMCPHandler(
		"test-service",
		cfg,
		new(MockUserMCPManager),
		new(MockUserTokenGetter),
		"http://localhost:8080",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockServerFunc,
	)

	req := httptest.NewRequest("GET", "/test-service/sse", nil)
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMCPHandler_ServeHTTP_RequiresUserToken_NoToken(t *testing.T) {
	mockTokenStore := new(MockUserTokenGetter)
	mockTokenStore.On("GetUserToken", mock.Anything, "test@example.com", "test-service").
		Return("", oauth.ErrUserTokenNotFound)

	cfg := &config.MCPClientConfig{
		RequiresUserToken: true,
	}

	mockServerFunc := func(name, version, baseURL string, config *config.MCPClientConfig) *client.Server {
		t.Fatal("Should not create server when token is missing")
		return nil
	}

	handler := newMCPHandler(
		"test-service",
		cfg,
		new(MockUserMCPManager),
		mockTokenStore,
		"http://localhost:8080",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockServerFunc,
	)

	req := httptest.NewRequest("GET", "/test-service/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	req = addUserToContext(req, "test@example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	mockTokenStore.AssertExpectations(t)
}

func TestMCPHandler_ServeHTTP_RequiresUserToken_WithToken_StdioServer(t *testing.T) {
	mockTokenStore := new(MockUserTokenGetter)
	mockTokenStore.On("GetUserToken", mock.Anything, "test@example.com", "test-service").
		Return("user-token-123", nil)

	mockUserManager := new(MockUserMCPManager)
	mockUserManager.On("CreateStdioInstance", mock.Anything, "test@example.com", "test-service", mock.Anything, "user-token-123").
		Return((*client.Client)(nil), errors.New("stdio not available in test"))

	cfg := &config.MCPClientConfig{
		Command:           "echo", 
		RequiresUserToken: true,
	}

	mockServerFunc := func(name, version, baseURL string, config *config.MCPClientConfig) *client.Server {
		// This would be called if CreateStdioInstance succeeded
		t.Fatal("Should not create server when stdio client creation fails")
		return nil
	}

	handler := newMCPHandler(
		"test-service",
		cfg,
		mockUserManager,
		mockTokenStore,
		"http://localhost:8080",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockServerFunc,
	)

	req := httptest.NewRequest("GET", "/test-service/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	req = addUserToContext(req, "test@example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// When stdio client creation fails, expect 503
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotEqual(t, http.StatusForbidden, w.Code, "Should not be 403 - token was found")
	mockTokenStore.AssertExpectations(t)
	mockUserManager.AssertExpectations(t)
}

func TestMCPHandler_ServeHTTP_NoUserToken_SSEServer(t *testing.T) {
	mockUserManager := new(MockUserMCPManager)
	
	// Create a mock server with a mock SSE handler
	mockServer := &client.Server{
		SSEServer: &mockSSEServer{},
	}
	
	mockUserManager.On("GetOrCreateSSEServer", mock.Anything, "test@example.com", "test-service", 
		mock.Anything, "", mock.Anything, "http://localhost:8080").
		Return(mockServer, nil)

	cfg := &config.MCPClientConfig{
		URL:               "http://example.com/mcp",
		RequiresUserToken: false,
	}

	mockServerFunc := func(name, version, baseURL string, config *config.MCPClientConfig) *client.Server {
		t.Fatal("Should not create server for SSE servers - should use cached instance")
		return nil
	}

	handler := newMCPHandler(
		"test-service",
		cfg,
		mockUserManager,
		new(MockUserTokenGetter),
		"http://localhost:8080",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockServerFunc,
	)

	req := httptest.NewRequest("GET", "/test-service/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	req = addUserToContext(req, "test@example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Mock SSE server responds with 200 OK
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "mock SSE response", w.Body.String())
	mockUserManager.AssertExpectations(t)
}

// mockSSEServer is a minimal implementation for testing
type mockSSEServer struct{}

func (m *mockSSEServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("mock SSE response"))
}

func TestMCPHandler_ServeHTTP_UserManagerError(t *testing.T) {
	mockUserManager := new(MockUserMCPManager)
	mockUserManager.On("GetOrCreateSSEServer", mock.Anything, "test@example.com", "test-service",
		mock.Anything, "", mock.Anything, "http://localhost:8080").
		Return((*client.Server)(nil), errors.New("mock SSE error"))

	cfg := &config.MCPClientConfig{
		URL:               "http://example.com/mcp",
		RequiresUserToken: false,
	}

	mockServerFunc := func(name, version, baseURL string, config *config.MCPClientConfig) *client.Server {
		t.Fatal("Should not create server when manager fails")
		return nil
	}

	handler := newMCPHandler(
		"test-service",
		cfg,
		mockUserManager,
		new(MockUserTokenGetter),
		"http://localhost:8080",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockServerFunc,
	)

	req := httptest.NewRequest("GET", "/test-service/sse", nil)
	req.Header.Set("Accept", "text/event-stream")
	req = addUserToContext(req, "test@example.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	mockUserManager.AssertExpectations(t)
}

func addUserToContext(req *http.Request, userEmail string) *http.Request {
	ctx := context.WithValue(req.Context(), oauth.GetUserContextKey(), userEmail)
	return req.WithContext(ctx)
}