package client

import (
	"context"
	"errors"
	"testing"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/testutil"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAddToMCPServerWithSession(t *testing.T) {
	ctx := context.Background()
	clientInfo := mcp.Implementation{Name: "test", Version: "1.0"}

	t.Run("session with tools support", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ServerInfo:      mcp.Implementation{Name: "test-server", Version: "1.0"},
			}, nil)

		tools := []mcp.Tool{
			{Name: "tool1", Description: "Test tool 1"},
			{Name: "tool2", Description: "Test tool 2"},
		}
		listToolsResult := &mcp.ListToolsResult{}
		listToolsResult.Tools = tools
		mockClient.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
			Return(listToolsResult, nil).Once()

		mockSession.On("SessionID").Return("test-session-123").Twice()

		mockSession.On("SetSessionTools", mock.MatchedBy(func(tools map[string]server.ServerTool) bool {
			return len(tools) == 2 &&
				tools["tool1"].Tool.Name == "tool1" &&
				tools["tool2"].Tool.Name == "tool2"
		})).Return()

		mockClient.On("ListPrompts", ctx, mock.AnythingOfType("mcp.ListPromptsRequest")).
			Return(&mcp.ListPromptsResult{}, nil)
		mockClient.On("ListResources", ctx, mock.AnythingOfType("mcp.ListResourcesRequest")).
			Return(&mcp.ListResourcesResult{}, nil)
		mockClient.On("ListResourceTemplates", ctx, mock.AnythingOfType("mcp.ListResourceTemplatesRequest")).
			Return(&mcp.ListResourceTemplatesResult{}, nil)

		err := client.AddToMCPServerWithSession(
			ctx,
			clientInfo,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		require.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockSession.AssertExpectations(t)
	})

	t.Run("session without tools support", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSession)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ServerInfo:      mcp.Implementation{Name: "test-server", Version: "1.0"},
			}, nil)

		err := client.AddToMCPServerWithSession(
			ctx,
			clientInfo,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "session does not support session-specific tools")
		mockClient.AssertExpectations(t)
	})

	t.Run("tool filtering with session", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
			options: &config.Options{
				ToolFilter: &config.ToolFilterConfig{
					Mode: config.ToolFilterModeAllow,
					List: []string{"tool1"},
				},
			},
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ServerInfo:      mcp.Implementation{Name: "test-server", Version: "1.0"},
			}, nil)

		tools := []mcp.Tool{
			{Name: "tool1", Description: "Test tool 1"},
			{Name: "tool2", Description: "Test tool 2"},
		}
		listToolsResult := &mcp.ListToolsResult{}
		listToolsResult.Tools = tools
		mockClient.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
			Return(listToolsResult, nil).Once()

		mockSession.On("SessionID").Return("test-session-456").Twice()

		mockSession.On("SetSessionTools", mock.MatchedBy(func(tools map[string]server.ServerTool) bool {
			return len(tools) == 1 && tools["tool1"].Tool.Name == "tool1"
		})).Return()

		mockClient.On("ListPrompts", ctx, mock.AnythingOfType("mcp.ListPromptsRequest")).
			Return(&mcp.ListPromptsResult{}, nil)
		mockClient.On("ListResources", ctx, mock.AnythingOfType("mcp.ListResourcesRequest")).
			Return(&mcp.ListResourcesResult{}, nil)
		mockClient.On("ListResourceTemplates", ctx, mock.AnythingOfType("mcp.ListResourceTemplatesRequest")).
			Return(&mcp.ListResourceTemplatesResult{}, nil)

		err := client.AddToMCPServerWithSession(
			ctx,
			clientInfo,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		require.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockSession.AssertExpectations(t)
	})

	t.Run("tool handler with token requirement", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ServerInfo:      mcp.Implementation{Name: "test-server", Version: "1.0"},
			}, nil)

		tools := []mcp.Tool{
			{Name: "tool1", Description: "Test tool 1"},
		}
		listToolsResult := &mcp.ListToolsResult{}
		listToolsResult.Tools = tools
		mockClient.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
			Return(listToolsResult, nil).Once()

		mockSession.On("SessionID").Return("test-session-789").Twice()

		var capturedHandler server.ToolHandlerFunc
		mockSession.On("SetSessionTools", mock.MatchedBy(func(tools map[string]server.ServerTool) bool {
			if len(tools) == 1 && tools["tool1"].Tool.Name == "tool1" {
				capturedHandler = tools["tool1"].Handler
				return true
			}
			return false
		})).Return()

		mockClient.On("ListPrompts", ctx, mock.AnythingOfType("mcp.ListPromptsRequest")).
			Return(&mcp.ListPromptsResult{}, nil)
		mockClient.On("ListResources", ctx, mock.AnythingOfType("mcp.ListResourcesRequest")).
			Return(&mcp.ListResourcesResult{}, nil)
		mockClient.On("ListResourceTemplates", ctx, mock.AnythingOfType("mcp.ListResourceTemplatesRequest")).
			Return(&mcp.ListResourceTemplatesResult{}, nil)

		err := client.AddToMCPServerWithSession(
			ctx,
			clientInfo,
			mockServer,
			"user@example.com",
			true,
			mockTokenStore,
			"test-server",
			"http://localhost",
			&config.TokenSetupConfig{
				DisplayName:  "Test Service",
				Instructions: "Get token from test service",
			},
			mockSession,
		)

		require.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockSession.AssertExpectations(t)

		t.Run("wrapped handler checks token", func(t *testing.T) {
			mockTokenStore.On("GetUserToken", ctx, "user@example.com", "test-server").
				Return("", errors.New("token not found"))

			toolRequest := mcp.CallToolRequest{}
			toolRequest.Params.Name = "tool1"
			result, err := capturedHandler(ctx, toolRequest)

			assert.NoError(t, err)
			assert.NotNil(t, result)
			// Check that result contains error about token required
			// The result should be a ToolResultError with the token required message
			mockTokenStore.AssertExpectations(t)
		})
	})
}

// Test that multiple sessions can have isolated tools
func TestSessionIsolation(t *testing.T) {
	ctx := context.Background()
	clientInfo := mcp.Implementation{Name: "test", Version: "1.0"}

	mockServer := server.NewMCPServer("test", "1.0")
	mockTokenStore := new(testutil.MockUserTokenStore)

	mockClient1 := new(testutil.MockMCPClient)
	mockSession1 := new(testutil.MockSessionWithTools)
	client1 := &Client{
		name:            "client1",
		needManualStart: false,
		client:          mockClient1,
	}

	mockClient2 := new(testutil.MockMCPClient)
	mockSession2 := new(testutil.MockSessionWithTools)
	client2 := &Client{
		name:            "client2",
		needManualStart: false,
		client:          mockClient2,
	}

	mockClient1.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
		Return(&mcp.InitializeResult{}, nil)
	listToolsResult1 := &mcp.ListToolsResult{}
	listToolsResult1.Tools = []mcp.Tool{{Name: "session1-tool", Description: "Tool for session 1"}}
	mockClient1.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
		Return(listToolsResult1, nil)
	mockClient1.On("ListPrompts", ctx, mock.AnythingOfType("mcp.ListPromptsRequest")).
		Return(&mcp.ListPromptsResult{}, nil)
	mockClient1.On("ListResources", ctx, mock.AnythingOfType("mcp.ListResourcesRequest")).
		Return(&mcp.ListResourcesResult{}, nil)
	mockClient1.On("ListResourceTemplates", ctx, mock.AnythingOfType("mcp.ListResourceTemplatesRequest")).
		Return(&mcp.ListResourceTemplatesResult{}, nil)

	mockSession1.On("SessionID").Return("session-1").Twice()
	mockSession1.On("SetSessionTools", mock.MatchedBy(func(tools map[string]server.ServerTool) bool {
		return len(tools) == 1 && tools["session1-tool"].Tool.Name == "session1-tool"
	})).Return()

	mockClient2.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
		Return(&mcp.InitializeResult{}, nil)
	listToolsResult2 := &mcp.ListToolsResult{}
	listToolsResult2.Tools = []mcp.Tool{{Name: "session2-tool", Description: "Tool for session 2"}}
	mockClient2.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
		Return(listToolsResult2, nil)
	mockClient2.On("ListPrompts", ctx, mock.AnythingOfType("mcp.ListPromptsRequest")).
		Return(&mcp.ListPromptsResult{}, nil)
	mockClient2.On("ListResources", ctx, mock.AnythingOfType("mcp.ListResourcesRequest")).
		Return(&mcp.ListResourcesResult{}, nil)
	mockClient2.On("ListResourceTemplates", ctx, mock.AnythingOfType("mcp.ListResourceTemplatesRequest")).
		Return(&mcp.ListResourceTemplatesResult{}, nil)

	mockSession2.On("SessionID").Return("session-2").Twice()
	mockSession2.On("SetSessionTools", mock.MatchedBy(func(tools map[string]server.ServerTool) bool {
		return len(tools) == 1 && tools["session2-tool"].Tool.Name == "session2-tool"
	})).Return()

	err1 := client1.AddToMCPServerWithSession(
		ctx, clientInfo, mockServer, "user1@example.com", false,
		mockTokenStore, "test-server", "http://localhost", nil, mockSession1,
	)
	require.NoError(t, err1)

	err2 := client2.AddToMCPServerWithSession(
		ctx, clientInfo, mockServer, "user2@example.com", false,
		mockTokenStore, "test-server", "http://localhost", nil, mockSession2,
	)
	require.NoError(t, err2)

	mockClient1.AssertExpectations(t)
	mockClient2.AssertExpectations(t)
	mockSession1.AssertExpectations(t)
	mockSession2.AssertExpectations(t)
}

func TestAddToMCPServerWithSession_ErrorHandling(t *testing.T) {
	ctx := context.Background()
	clientInfo := mcp.Implementation{Name: "test", Version: "1.0"}

	t.Run("initialization failure", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(nil, errors.New("initialization failed"))

		err := client.AddToMCPServerWithSession(
			ctx, clientInfo, mockServer, "user@example.com", false,
			mockTokenStore, "test-server", "http://localhost", nil, mockSession,
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "initialization failed")
		mockClient.AssertExpectations(t)
	})

	t.Run("tool listing failure", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{}, nil)

		mockClient.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
			Return(nil, errors.New("failed to list tools"))

		mockSession.On("SessionID").Return("test-session").Once()

		err := client.AddToMCPServerWithSession(
			ctx, clientInfo, mockServer, "user@example.com", false,
			mockTokenStore, "test-server", "http://localhost", nil, mockSession,
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list tools")
		mockClient.AssertExpectations(t)
	})
}