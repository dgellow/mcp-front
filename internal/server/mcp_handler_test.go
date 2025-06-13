package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockMCPClientInterface is a mock implementation of client.MCPClientInterface
type MockMCPClientInterface struct {
	mock.Mock
}

func (m *MockMCPClientInterface) Initialize(ctx context.Context, request mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.InitializeResult), args.Error(1)
}

func (m *MockMCPClientInterface) ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListToolsResult), args.Error(1)
}

func (m *MockMCPClientInterface) CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.CallToolResult), args.Error(1)
}

func (m *MockMCPClientInterface) ListPrompts(ctx context.Context, request mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListPromptsResult), args.Error(1)
}

func (m *MockMCPClientInterface) GetPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.GetPromptResult), args.Error(1)
}

func (m *MockMCPClientInterface) ListResources(ctx context.Context, request mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListResourcesResult), args.Error(1)
}

func (m *MockMCPClientInterface) ReadResource(ctx context.Context, request mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ReadResourceResult), args.Error(1)
}

func (m *MockMCPClientInterface) ListResourceTemplates(ctx context.Context, request mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListResourceTemplatesResult), args.Error(1)
}

func (m *MockMCPClientInterface) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMCPClientInterface) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMCPClientInterface) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockClient is a mock implementation of mcpClient interface
type MockClient struct {
	mock.Mock
}

func (m *MockClient) AddToMCPServer(ctx context.Context, info mcp.Implementation, srv *server.MCPServer) error {
	args := m.Called(ctx, info, srv)
	return args.Error(0)
}

func (m *MockClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// mockTokenStore implements oauth.UserTokenStore for testing
type mockTokenStore struct{}

func (m *mockTokenStore) GetUserToken(ctx context.Context, userEmail, service string) (string, error) {
	return "", nil
}
func (m *mockTokenStore) SetUserToken(ctx context.Context, userEmail, service, token string) error {
	return nil
}
func (m *mockTokenStore) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	return nil
}
func (m *mockTokenStore) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	return nil, nil
}

func TestSSEConnectionCleanup(t *testing.T) {
	// Create a mock transport
	mockTransport := new(MockMCPClientInterface)
	
	// Set up expectations
	mockTransport.On("Start", mock.Anything).Return(nil)
	mockTransport.On("Initialize", mock.Anything, mock.Anything).Return(&mcp.InitializeResult{}, nil)
	mockTransport.On("ListTools", mock.Anything, mock.Anything).Return(&mcp.ListToolsResult{Tools: []mcp.Tool{}}, nil)
	mockTransport.On("ListPrompts", mock.Anything, mock.Anything).Return(&mcp.ListPromptsResult{Prompts: []mcp.Prompt{}}, nil)
	mockTransport.On("ListResources", mock.Anything, mock.Anything).Return(&mcp.ListResourcesResult{Resources: []mcp.Resource{}}, nil)
	mockTransport.On("ListResourceTemplates", mock.Anything, mock.Anything).Return(&mcp.ListResourceTemplatesResult{ResourceTemplates: []mcp.ResourceTemplate{}}, nil)
	
	// This is the key assertion - Close should be called
	mockTransport.On("Close").Return(nil).Once()
	
	// Create test config
	serverConfig := &config.MCPClientConfig{
		URL:           "https://example.com/sse",
		TransportType: config.MCPClientTypeSSE,
	}

	// Create handler with mock transport injector
	handler := &MCPHandler{
		serverName:   "test-server",
		serverConfig: serverConfig,
		tokenStore:   &mockTokenStore{},
		setupBaseURL: "https://test.example.com",
		info: mcp.Implementation{
			Name:    "test",
			Version: "1.0",
		},
		newClient: func(name string, conf *config.MCPClientConfig) (*client.Client, error) {
			// Use our mock as the transport
			return client.NewMCPClientWith(name, conf, func(_ *config.MCPClientConfig) (client.MCPClientInterface, error) {
				return mockTransport, nil
			})
		},
	}

	// Create a context that we'll cancel to simulate request cancellation
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, oauth.GetUserContextKey(), "test@example.com")
	req := httptest.NewRequest("GET", "/test/sse", nil).WithContext(ctx)
	
	// Create response recorder
	rr := httptest.NewRecorder()

	// Start the handler in a goroutine
	done := make(chan bool)
	go func() {
		handler.ServeHTTP(rr, req)
		done <- true
	}()

	// Give the handler time to set up the cleanup goroutine
	time.Sleep(100 * time.Millisecond)

	// Cancel the context to simulate client disconnect
	cancel()

	// Give cleanup goroutine time to run
	time.Sleep(100 * time.Millisecond)

	// Verify all expectations were met
	mockTransport.AssertExpectations(t)
}

func TestStdioConnectionNoCleanup(t *testing.T) {
	// Create a mock transport
	mockTransport := new(MockMCPClientInterface)
	
	// Set up expectations
	// Note: Start is not called for stdio
	mockTransport.On("Initialize", mock.Anything, mock.Anything).Return(&mcp.InitializeResult{}, nil)
	mockTransport.On("ListTools", mock.Anything, mock.Anything).Return(&mcp.ListToolsResult{Tools: []mcp.Tool{}}, nil)
	mockTransport.On("ListPrompts", mock.Anything, mock.Anything).Return(&mcp.ListPromptsResult{Prompts: []mcp.Prompt{}}, nil)
	mockTransport.On("ListResources", mock.Anything, mock.Anything).Return(&mcp.ListResourcesResult{Resources: []mcp.Resource{}}, nil)
	mockTransport.On("ListResourceTemplates", mock.Anything, mock.Anything).Return(&mcp.ListResourceTemplatesResult{ResourceTemplates: []mcp.ResourceTemplate{}}, nil)
	
	// For stdio, Close should be called due to defer
	mockTransport.On("Close").Return(nil).Once()
	
	// Create test config for stdio
	serverConfig := &config.MCPClientConfig{
		Command:       "echo",
		Args:          []string{"test"},
		TransportType: config.MCPClientTypeStdio,
	}

	// Create handler
	handler := &MCPHandler{
		serverName:   "test-server",
		serverConfig: serverConfig,
		tokenStore:   &mockTokenStore{},
		setupBaseURL: "https://test.example.com",
		info: mcp.Implementation{
			Name:    "test",
			Version: "1.0",
		},
		newClient: func(name string, conf *config.MCPClientConfig) (*client.Client, error) {
			// Use our mock as the transport
			return client.NewMCPClientWith(name, conf, func(_ *config.MCPClientConfig) (client.MCPClientInterface, error) {
				return mockTransport, nil
			})
		},
	}

	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "test@example.com")
	req := httptest.NewRequest("POST", "/test/stdio", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	// This should complete and close the client immediately (deferred)
	handler.ServeHTTP(rr, req)

	// Verify all expectations were met
	mockTransport.AssertExpectations(t)
}

func TestSSEConnectionCleanupOnError(t *testing.T) {
	// Create a mock that fails during initialization
	mockTransport := new(MockMCPClientInterface)
	
	// Set up expectations
	mockTransport.On("Start", mock.Anything).Return(nil)
	mockTransport.On("Initialize", mock.Anything, mock.Anything).Return(nil, errors.New("initialization failed"))
	
	// Close should still be called on error
	mockTransport.On("Close").Return(nil).Once()
	
	serverConfig := &config.MCPClientConfig{
		URL:           "https://example.com/sse",
		TransportType: config.MCPClientTypeSSE,
	}

	handler := &MCPHandler{
		serverName:   "test-server",
		serverConfig: serverConfig,
		tokenStore:   &mockTokenStore{},
		setupBaseURL: "https://test.example.com",
		info: mcp.Implementation{
			Name:    "test",
			Version: "1.0",
		},
		newClient: func(name string, conf *config.MCPClientConfig) (*client.Client, error) {
			return client.NewMCPClientWith(name, conf, func(_ *config.MCPClientConfig) (client.MCPClientInterface, error) {
				return mockTransport, nil
			})
		},
	}

	ctx := context.WithValue(context.Background(), oauth.GetUserContextKey(), "test@example.com")
	req := httptest.NewRequest("GET", "/test/sse", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should have returned an error response
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	// Verify all expectations were met
	mockTransport.AssertExpectations(t)
}