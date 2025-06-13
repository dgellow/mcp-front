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
	"github.com/stretchr/testify/require"
)

// mockTokenStore implements oauth.UserTokenStore for testing
type mockTokenStore struct {
	mock.Mock
}

func (m *mockTokenStore) GetUserToken(ctx context.Context, userEmail, service string) (string, error) {
	args := m.Called(ctx, userEmail, service)
	return args.String(0), args.Error(1)
}

func (m *mockTokenStore) SetUserToken(ctx context.Context, userEmail, service, token string) error {
	args := m.Called(ctx, userEmail, service, token)
	return args.Error(0)
}

func (m *mockTokenStore) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	args := m.Called(ctx, userEmail, service)
	return args.Error(0)
}

func (m *mockTokenStore) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	args := m.Called(ctx, userEmail)
	return args.Get(0).([]string), args.Error(1)
}

func TestMCPHandler_ServeHTTP_NoAuth(t *testing.T) {
	createClientCalled := false
	mockCreateClient := func(name string, config *config.MCPClientConfig) (*client.Client, error) {
		createClientCalled = true
		assert.Equal(t, "test-server", name)
		return nil, errors.New("network error")
	}

	handler := NewMCPHandlerWith(
		"test-server",
		&config.MCPClientConfig{
			URL: "https://example.com",
		},
		nil,
		"https://test.example.com",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockCreateClient,
	)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to connect to service")
	assert.True(t, createClientCalled, "createClient should have been called")
}

func TestMCPHandler_ServeHTTP_WithOAuth_UserPresent(t *testing.T) {
	tokenStore := new(mockTokenStore)
	
	createClientCalled := false
	mockCreateClient := func(name string, config *config.MCPClientConfig) (*client.Client, error) {
		createClientCalled = true
		return nil, errors.New("network error")
	}
	
	handler := NewMCPHandlerWith(
		"test-server",
		&config.MCPClientConfig{},
		tokenStore,
		"https://test.example.com",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockCreateClient,
	)

	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "user@example.com")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.True(t, createClientCalled)
}

func TestMCPHandler_ServeHTTP_UserTokenRequired_NotFound(t *testing.T) {
	tokenStore := new(mockTokenStore)
	tokenStore.On("GetUserToken", mock.Anything, "user@example.com", "test-server").
		Return("", oauth.ErrUserTokenNotFound)

	handler := NewMCPHandlerWith(
		"test-server",
		&config.MCPClientConfig{
			RequiresUserToken: true,
		},
		tokenStore,
		"https://test.example.com",
		mcp.Implementation{Name: "test", Version: "1.0"},
		nil,
	)

	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "user@example.com")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	
	body := w.Body.String()
	assert.Contains(t, body, "event: error")
	assert.Contains(t, body, "token_required")
	assert.Contains(t, body, "/my/tokens")

	tokenStore.AssertExpectations(t)
}

func TestMCPHandler_ServeHTTP_ClientCreationFails(t *testing.T) {
	tokenStore := new(mockTokenStore)
	
	mockCreateClient := func(name string, config *config.MCPClientConfig) (*client.Client, error) {
		return nil, errors.New("connection failed")
	}

	handler := NewMCPHandlerWith(
		"test-server",
		&config.MCPClientConfig{},
		tokenStore,
		"https://test.example.com",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockCreateClient,
	)

	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "user@example.com")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to connect to service")
}

func TestMCPHandler_ServeHTTP_UserTokenSubstitution(t *testing.T) {
	tokenStore := new(mockTokenStore)
	
	tokenStore.On("GetUserToken", mock.Anything, "user@example.com", "test-server").
		Return("secret-token-123", nil)

	var capturedConfig *config.MCPClientConfig
	mockCreateClient := func(name string, cfg *config.MCPClientConfig) (*client.Client, error) {
		capturedConfig = cfg
		return nil, errors.New("mock error - not testing client logic")
	}

	originalConfig := &config.MCPClientConfig{
		RequiresUserToken: true,
		Env: map[string]string{
			"AUTH_TOKEN": "Bearer {{token}}",
			"OTHER_VAR":  "unchanged",
		},
		EnvNeedsToken: map[string]bool{
			"AUTH_TOKEN": true,
			"OTHER_VAR":  false,
		},
	}

	handler := NewMCPHandlerWith(
		"test-server",
		originalConfig,
		tokenStore,
		"https://test.example.com",
		mcp.Implementation{Name: "test", Version: "1.0"},
		mockCreateClient,
	)

	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "user@example.com")
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.NotNil(t, capturedConfig)
	assert.Equal(t, "Bearer secret-token-123", capturedConfig.Env["AUTH_TOKEN"])
	assert.Equal(t, "unchanged", capturedConfig.Env["OTHER_VAR"])
	
	assert.Equal(t, "Bearer {{token}}", originalConfig.Env["AUTH_TOKEN"])

	tokenStore.AssertExpectations(t)
}

func TestMCPHandler_TokenSetupInstructions(t *testing.T) {
	tokenStore := new(mockTokenStore)
	tokenStore.On("GetUserToken", mock.Anything, "user@example.com", "notion").
		Return("", oauth.ErrUserTokenNotFound)

	handler := NewMCPHandlerWith(
		"notion",
		&config.MCPClientConfig{
			RequiresUserToken: true,
			TokenSetup: &config.TokenSetupConfig{
				DisplayName:  "Notion API",
				Instructions: "Get your token from https://notion.so/integrations",
			},
		},
		tokenStore,
		"https://myapp.com",
		mcp.Implementation{Name: "test", Version: "1.0"},
		nil,
	)

	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "user@example.com")
	req := httptest.NewRequest("GET", "/notion", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	body := w.Body.String()
	assert.Contains(t, body, "Notion API")
	assert.Contains(t, body, "https://notion.so/integrations")
	assert.Contains(t, body, "https://myapp.com/my/tokens")

	tokenStore.AssertExpectations(t)
}

func TestMCPHandler_UserTokenRequired_NoUser(t *testing.T) {
	tokenStore := new(mockTokenStore)
	
	handler := NewMCPHandlerWith(
		"test-server",
		&config.MCPClientConfig{
			RequiresUserToken: true,
		},
		tokenStore,
		"https://test.example.com",
		mcp.Implementation{Name: "test", Version: "1.0"},
		nil,
	)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authentication required")
}