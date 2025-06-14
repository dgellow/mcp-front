package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	internalclient "github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStdioMCPDirect tests direct stdio communication with MCP server
func TestStdioMCPDirect(t *testing.T) {
	closeDB := startTestDB(t)
	defer closeDB()

	waitForDB(t)

	// Load config
	cfg, err := config.Load("config/config.test.json")
	require.NoError(t, err, "Failed to load config")

	// Get postgres server config
	postgresConfig, exists := cfg.MCPServers["postgres"]
	require.True(t, exists, "postgres server not found in config")

	// Create stdio MCP client
	envs := make([]string, 0, len(postgresConfig.Env))
	for k, v := range postgresConfig.Env {
		envs = append(envs, k+"="+v)
	}

	stdioTransport := transport.NewStdio(postgresConfig.Command, envs, postgresConfig.Args...)
	stdioClient := client.NewClient(stdioTransport)
	defer stdioClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = stdioClient.Start(ctx)
	require.NoError(t, err, "Failed to start stdio client")

	// Initialize the connection
	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}

	initResult, err := stdioClient.Initialize(ctx, initRequest)
	require.NoError(t, err, "Failed to initialize")
	t.Logf("Server info: %+v", initResult.ServerInfo)

	// List tools - this reads from the stdio server
	toolsRequest := mcp.ListToolsRequest{}
	toolsResult, err := stdioClient.ListTools(ctx, toolsRequest)
	require.NoError(t, err, "Failed to list tools")

	t.Logf("Available tools: %d", len(toolsResult.Tools))
	var queryTool *mcp.Tool
	for _, tool := range toolsResult.Tools {
		t.Logf("  Tool: %s - %s", tool.Name, tool.Description)
		if tool.Name == "query" {
			queryTool = &tool

		}
	}
	require.NotNil(t, queryTool, "query tool not found")

	// Execute a query - this writes to stdio and reads the response
	callRequest := mcp.CallToolRequest{}
	callRequest.Params.Name = "query"
	callRequest.Params.Arguments = map[string]interface{}{
		"sql": "SELECT 1 as test_value",
	}

	// Log the request to debug
	reqJSON, _ := json.MarshalIndent(callRequest, "", "  ")
	t.Logf("Sending tool call request:\n%s", string(reqJSON))

	result, err := stdioClient.CallTool(ctx, callRequest)
	require.NoError(t, err, "Failed to call query tool")
	require.NotNil(t, result, "Expected result from query")

	// Log the result
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("Query result:\n%s", string(resultJSON))

	// Verify we got a response
	assert.NotEmpty(t, result.Content, "Expected content in result")

	// List resources
	resourcesRequest := mcp.ListResourcesRequest{}
	resourcesResult, err := stdioClient.ListResources(ctx, resourcesRequest)
	require.NoError(t, err, "Failed to list resources")

	t.Logf("Available resources: %d", len(resourcesResult.Resources))
	for _, resource := range resourcesResult.Resources {
		t.Logf("  Resource: %s - %s", resource.Name, resource.Description)
	}
}

// TestSSEToStdioBridge tests the SSE-to-stdio bridge functionality
func TestSSEToStdioBridge(t *testing.T) {
	closeDB := startTestDB(t)
	defer closeDB()

	waitForDB(t)

	// Load config
	cfg, err := config.Load("config/config.test.json")
	require.NoError(t, err, "Failed to load config")

	// Get postgres server config
	postgresConfig, exists := cfg.MCPServers["postgres"]
	require.True(t, exists, "postgres server not found in config")

	// Create stdio transport and client directly
	envs := make([]string, 0, len(postgresConfig.Env))
	for k, v := range postgresConfig.Env {
		envs = append(envs, k+"="+v)
	}

	stdioTransport := transport.NewStdio(postgresConfig.Command, envs, postgresConfig.Args...)
	stdioClient := client.NewClient(stdioTransport)
	defer stdioClient.Close()

	// Create MCP server
	mcpServer := server.NewMCPServer(
		"test-server",
		"1.0.0",
		server.WithLogging(),
	)

	// Create SSE server without a fixed base URL (we'll set it later)
	sseServer := server.NewSSEServer(mcpServer,
		server.WithStaticBasePath("test"),
	)

	// Start stdio client
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = stdioClient.Start(ctx)
	require.NoError(t, err, "Failed to start stdio client")

	// Initialize the connection
	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}

	initResult, err := stdioClient.Initialize(ctx, initRequest)
	require.NoError(t, err, "Failed to initialize")
	t.Logf("Server info: %+v", initResult.ServerInfo)

	// List tools to verify connection works
	toolsRequest := mcp.ListToolsRequest{}
	toolsResult, err := stdioClient.ListTools(ctx, toolsRequest)
	require.NoError(t, err, "Failed to list tools")
	t.Logf("Found %d tools", len(toolsResult.Tools))

	// Register stdio client tools with the MCP server
	for _, tool := range toolsResult.Tools {
		t.Logf("Registering tool: %s", tool.Name)
		mcpServer.AddTool(tool, stdioClient.CallTool)
	}

	// Test that httptest.Recorder supports Flusher interface
	t.Log("\nTesting Flusher support...")
	w := httptest.NewRecorder()
	var writer http.ResponseWriter = w
	_, ok := writer.(http.Flusher)
	require.True(t, ok, "httptest.Recorder should implement Flusher")

	// Now let's test the SSE endpoint with httptest.Recorder
	// We need to run it in a goroutine with timeout since it might block
	t.Log("\nTesting SSE with httptest.Recorder...")
	req := httptest.NewRequest("GET", "/test/sse", nil)
	w2 := httptest.NewRecorder()

	// Run in goroutine with timeout
	done := make(chan bool)
	go func() {
		sseServer.ServeHTTP(w2, req)
		done <- true
	}()

	select {
	case <-done:
		resp := w2.Result()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response: %d - %s", resp.StatusCode, string(body))
	case <-time.After(2 * time.Second):
		t.Log("SSE server blocked as expected with httptest.Recorder")
	}

	// Now test with a real HTTP server
	t.Log("\nTesting SSE with real HTTP server...")

	// Create a context that we'll cancel to stop the SSE connection
	sseCtx, sseCancel := context.WithCancel(context.Background())
	defer sseCancel()

	// Start a test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Override the request context so we can control when to stop
		r = r.WithContext(sseCtx)
		sseServer.ServeHTTP(w, r)
	}))
	defer ts.Close()

	// Now recreate the SSE server with the correct base URL
	sseServer = server.NewSSEServer(mcpServer,
		server.WithStaticBasePath("test"),
		server.WithBaseURL(ts.URL),
	)

	// Make a real HTTP request to test SSE
	sseReq, err := http.NewRequest("GET", ts.URL+"/test/sse", nil)
	require.NoError(t, err)
	sseReq.Header.Set("Accept", "text/event-stream")

	// Use a client without timeout for SSE
	httpClient := &http.Client{}
	sseResp, err := httpClient.Do(sseReq)
	require.NoError(t, err)
	defer sseResp.Body.Close()

	t.Logf("SSE Response status: %d", sseResp.StatusCode)
	t.Logf("SSE Response headers: %v", sseResp.Header)

	if sseResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(sseResp.Body)
		t.Fatalf("SSE request failed: %d - %s", sseResp.StatusCode, string(respBody))
	}

	// Read SSE stream to get endpoint
	scanner := bufio.NewScanner(sseResp.Body)
	var endpoint string
	for scanner.Scan() {
		line := scanner.Text()
		t.Logf("SSE line: %s", line)

		// Look for the data line after event: endpoint
		if strings.HasPrefix(line, "data: ") {
			endpoint = strings.TrimPrefix(line, "data: ")
			t.Logf("Got endpoint: %s", endpoint)
			break
		}

		// Stop after a few lines to avoid hanging
		if len(endpoint) == 0 && scanner.Text() == "" {
			continue // Empty line between event and data
		}
	}

	require.NotEmpty(t, endpoint, "Should receive an endpoint URL")
	require.Contains(t, endpoint, "http", "Endpoint should be an HTTP URL")

	// Now use the endpoint to send an MCP request to call the SQL tool
	t.Log("\nTesting SQL tool call through SSE-to-stdio bridge...")

	// Create a tool call request
	toolCallRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "query",
			"arguments": map[string]interface{}{
				"sql": "SELECT 'Hello from SSE-stdio bridge' as message, 42 as answer",
			},
		},
	}

	reqBody, err := json.Marshal(toolCallRequest)
	require.NoError(t, err)

	// Send the request to the endpoint
	msgReq, err := http.NewRequest("POST", endpoint, strings.NewReader(string(reqBody)))
	require.NoError(t, err)
	msgReq.Header.Set("Content-Type", "application/json")

	msgResp, err := httpClient.Do(msgReq)
	require.NoError(t, err)
	defer msgResp.Body.Close()

	t.Logf("Tool call response status: %d", msgResp.StatusCode)

	// Read the response
	respBody, err := io.ReadAll(msgResp.Body)
	require.NoError(t, err)
	t.Logf("Tool call response body length: %d", len(respBody))
	t.Logf("Tool call response: %s", string(respBody))

	// If response is empty (202 Accepted), we might need to poll or read from SSE
	if len(respBody) == 0 && msgResp.StatusCode == 202 {
		t.Log("Got 202 Accepted with empty body, reading from SSE stream for response...")

		// Continue reading from the SSE stream for the response
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("SSE response line: %s", line)

			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				// Try to parse as JSON
				var msg map[string]interface{}
				if err := json.Unmarshal([]byte(data), &msg); err == nil {
					// Check if this is our response
					if id, ok := msg["id"]; ok && id == float64(1) {
						t.Logf("Got response for our request: %s", data)
						respBody = []byte(data)
						break
					}
				}
			}
		}
	}

	// Parse the response
	var toolResponse map[string]interface{}
	err = json.Unmarshal(respBody, &toolResponse)
	require.NoError(t, err, "Failed to parse tool response")

	// Check for successful result
	result, ok := toolResponse["result"].(map[string]interface{})
	require.True(t, ok, "Response should have a result field")

	content, ok := result["content"].([]interface{})
	require.True(t, ok, "Result should have content array")
	require.NotEmpty(t, content, "Content should not be empty")

	// Check the SQL result
	firstContent := content[0].(map[string]interface{})
	contentType, _ := firstContent["type"].(string)
	require.Equal(t, "text", contentType)

	text, _ := firstContent["text"].(string)
	t.Logf("SQL query result: %s", text)
	require.Contains(t, text, "Hello from SSE-stdio bridge", "Should contain our query result")
	require.Contains(t, text, "42", "Should contain the answer")

	// Cancel the context to close the SSE connection gracefully
	sseCancel()

	t.Log("\nSSE-to-stdio bridge test with SQL tool completed successfully!")
}

// TestSSEToStdioBridgeInternal tests the SSE-to-stdio bridge using our internal implementation
func TestSSEToStdioBridgeInternal(t *testing.T) {
	closeDB := startTestDB(t)
	defer closeDB()

	waitForDB(t)

	// Load config
	cfg, err := config.Load("config/config.test.json")
	require.NoError(t, err, "Failed to load config")

	// Get postgres server config
	postgresConfig, exists := cfg.MCPServers["postgres"]
	require.True(t, exists, "postgres server not found in config")

	// Use our internal client creation
	mcpClient, err := internalclient.NewMCPClient("postgres", postgresConfig)
	require.NoError(t, err, "Failed to create MCP client")
	defer mcpClient.Close()

	// We need to track sessions so message endpoints can find their stdio process
	sessions := make(map[string]*server.MCPServer)
	var sessionMutex sync.Mutex
	
	// Create hooks to capture session registration
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(ctx context.Context, session server.ClientSession) {
		sessionID := session.SessionID()
		t.Logf("Session registered: %s", sessionID)
		
		// Create a new MCP server for this session that's connected to our stdio client
		mcpServerForSession := server.NewMCPServer("postgres-session", "dev",
			server.WithPromptCapabilities(true),
			server.WithResourceCapabilities(true, true),
			server.WithToolCapabilities(true),
			server.WithLogging(),
		)
		
		// Connect our stdio client to this session's MCP server
		err := mcpClient.AddToMCPServer(context.Background(), mcp.Implementation{
			Name:    "test-server",
			Version: "1.0.0",
		}, mcpServerForSession)
		if err != nil {
			t.Logf("Failed to connect client to session MCP server: %v", err)
		}
		
		// Store the session
		sessionMutex.Lock()
		sessions[sessionID] = mcpServerForSession
		sessionMutex.Unlock()
	})

	// Create MCP server with hooks
	mcpServer := server.NewMCPServer("postgres", "dev",
		server.WithHooks(hooks),
		server.WithPromptCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithToolCapabilities(true),
		server.WithLogging(),
	)
	
	// Test with a real HTTP server that simulates our middleware
	t.Log("\nTesting SSE with our internal implementation and simulated middleware...")

	// We'll set these after we have the test server URL
	var sseServer *server.SSEServer
	var testServerURL string
	
	// Start a test server first to get the URL
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle message requests differently than SSE requests
		if strings.Contains(r.URL.Path, "/message") {
			sessionID := r.URL.Query().Get("sessionId")
			
			sessionMutex.Lock()
			sessionMCPServer, ok := sessions[sessionID]
			sessionMutex.Unlock()
			
			if ok && sessionMCPServer != nil {
				// Use the session-specific MCP server's SSE server
				sessionSSE := server.NewSSEServer(sessionMCPServer,
					server.WithStaticBasePath("postgres"),
					server.WithBaseURL(testServerURL),
				)
				sessionSSE.ServeHTTP(w, r)
				return
			}
		}
		
		// For SSE requests, use the main SSE server
		// Wrap with our responseWriterDelegator like the logger middleware does
		wrapped := &responseWriterDelegator{
			ResponseWriter: w,
			status:         http.StatusOK,
		}

		// Log the wrapper type like we do in the real handler
		var iface http.ResponseWriter = wrapped
		t.Logf("ResponseWriter type: %T, implements Flusher: %v", iface, func() bool {
			_, ok := iface.(http.Flusher)
			return ok
		}())

		sseServer.ServeHTTP(wrapped, r)
	}))
	defer ts.Close()
	
	// Store the URL for use in the handler
	testServerURL = ts.URL

	// Now create the SSE server with the correct base URL
	sseServer = server.NewSSEServer(mcpServer,
		server.WithStaticBasePath("postgres"),
		server.WithBaseURL(ts.URL),
	)

	// Make SSE request
	sseReq, err := http.NewRequest("GET", ts.URL+"/postgres/sse", nil)
	require.NoError(t, err)
	sseReq.Header.Set("Accept", "text/event-stream")

	httpClient := &http.Client{}
	sseResp, err := httpClient.Do(sseReq)
	require.NoError(t, err)
	defer sseResp.Body.Close()

	t.Logf("SSE Response status: %d", sseResp.StatusCode)
	t.Logf("SSE Response headers: %v", sseResp.Header)

	if sseResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(sseResp.Body)
		t.Fatalf("SSE request failed: %d - %s", sseResp.StatusCode, string(respBody))
	}

	// Read SSE stream to get endpoint
	scanner := bufio.NewScanner(sseResp.Body)
	var endpoint string
	for scanner.Scan() {
		line := scanner.Text()
		t.Logf("SSE line: %s", line)

		if strings.HasPrefix(line, "data: ") {
			endpoint = strings.TrimPrefix(line, "data: ")
			t.Logf("Got endpoint: %s", endpoint)
			break
		}
	}

	require.NotEmpty(t, endpoint, "Should receive an endpoint URL")

	// Make SQL query through the endpoint
	toolCallRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "query",
			"arguments": map[string]interface{}{
				"sql": "SELECT 'Hello from internal implementation' as message, 42 as answer",
			},
		},
	}

	reqBody, err := json.Marshal(toolCallRequest)
	require.NoError(t, err)

	msgReq, err := http.NewRequest("POST", endpoint, strings.NewReader(string(reqBody)))
	require.NoError(t, err)
	msgReq.Header.Set("Content-Type", "application/json")

	msgResp, err := httpClient.Do(msgReq)
	require.NoError(t, err)
	defer msgResp.Body.Close()

	t.Logf("Tool call response status: %d", msgResp.StatusCode)

	respBody, err := io.ReadAll(msgResp.Body)
	require.NoError(t, err)

	// Handle 202 response
	if len(respBody) == 0 && msgResp.StatusCode == 202 {
		t.Log("Got 202 Accepted, reading from SSE stream for response...")

		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"id":1`) {
				respBody = []byte(strings.TrimPrefix(line, "data: "))
				break
			}
		}
	}

	// Parse and verify response
	var toolResponse map[string]interface{}
	err = json.Unmarshal(respBody, &toolResponse)
	require.NoError(t, err, "Failed to parse tool response")

	t.Logf("Tool response: %+v", toolResponse)

	result, ok := toolResponse["result"].(map[string]interface{})
	require.True(t, ok, "Response should have a result field")

	content, ok := result["content"].([]interface{})
	require.True(t, ok, "Result should have content array")
	require.NotEmpty(t, content, "Content should not be empty")

	firstContent := content[0].(map[string]interface{})
	text, _ := firstContent["text"].(string)
	t.Logf("SQL query result: %s", text)
	require.Contains(t, text, "Hello from internal implementation")
	require.Contains(t, text, "42")

	t.Log("\nSSE-to-stdio bridge test with internal implementation completed!")
}

// responseWriterDelegator mimics our middleware wrapper
type responseWriterDelegator struct {
	http.ResponseWriter
	status      int
	written     int
	wroteHeader bool
}

func (r *responseWriterDelegator) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseWriterDelegator) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += n
	return n, err
}

func (r *responseWriterDelegator) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *responseWriterDelegator) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
