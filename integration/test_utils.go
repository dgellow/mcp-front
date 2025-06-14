package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// getDockerComposeCommand returns the appropriate docker compose command
func getDockerComposeCommand() string {
	// Check if docker compose v2 is available
	cmd := exec.Command("docker", "compose", "version")
	if err := cmd.Run(); err == nil {
		return "docker compose"
	}
	return "docker-compose"
}

// execDockerCompose executes docker compose with the given arguments
func execDockerCompose(args ...string) *exec.Cmd {
	dcCmd := getDockerComposeCommand()
	if dcCmd == "docker compose" {
		allArgs := append([]string{"compose"}, args...)
		return exec.Command("docker", allArgs...)
	}
	return exec.Command("docker-compose", args...)
}

// MCPClient simulates an MCP client for testing
type MCPClient struct {
	baseURL         string
	token           string
	sseConn         io.ReadCloser
	messageEndpoint string
	sseScanner      *bufio.Scanner
	sessionID       string
}

// NewMCPClient creates a new MCP client for testing
func NewMCPClient(baseURL string) *MCPClient {
	return &MCPClient{
		baseURL: baseURL,
	}
}

// Authenticate sets up authentication for the client
func (c *MCPClient) Authenticate() error {
	c.token = "test-token"
	return nil
}

// SetAuthToken sets a specific auth token for the client
func (c *MCPClient) SetAuthToken(token string) {
	c.token = token
}

// Connect establishes an SSE connection and retrieves the message endpoint
func (c *MCPClient) Connect() error {
	// Close any existing connection
	if c.sseConn != nil {
		c.sseConn.Close()
		c.sseConn = nil
		c.messageEndpoint = ""
	}

	sseURL := c.baseURL + "/postgres/sse"
	tracef("Connect: requesting %s", sseURL)

	req, err := http.NewRequest("GET", sseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create SSE request: %v", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Cache-Control", "no-cache")
	tracef("Connect: headers set, making request")

	// Don't use a timeout on the client for SSE
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %v", err)
	}

	tracef("Connect: got response status %d", resp.StatusCode)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("SSE connection returned %d: %s", resp.StatusCode, string(body))
	}

	// Store the connection
	c.sseConn = resp.Body
	c.sseScanner = bufio.NewScanner(resp.Body)

	// Read initial SSE messages to get the endpoint
	for c.sseScanner.Scan() {
		line := c.sseScanner.Text()
		tracef("Connect: SSE line: %s", line)

		// Look for data lines containing the endpoint
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			if strings.Contains(data, "http://") || strings.Contains(data, "https://") {
				c.messageEndpoint = data

				// Extract session ID from endpoint URL
				if u, err := url.Parse(data); err == nil {
					c.sessionID = u.Query().Get("sessionId")
				}

				tracef("Connect: found endpoint: %s", c.messageEndpoint)
				break
			}
		}
	}

	if c.messageEndpoint == "" {
		c.sseConn.Close()
		c.sseConn = nil
		return fmt.Errorf("no message endpoint received")
	}

	tracef("Connect: successfully connected to MCP server")
	return nil
}

// ValidateBackendConnectivity checks if we can connect to the MCP server
func (c *MCPClient) ValidateBackendConnectivity() error {
	return c.Connect()
}

// Close closes the SSE connection
func (c *MCPClient) Close() {
	if c.sseConn != nil {
		c.sseConn.Close()
		c.sseConn = nil
		c.messageEndpoint = ""
		c.sseScanner = nil
	}
}

// SendMCPRequest sends an MCP JSON-RPC request and returns the response
func (c *MCPClient) SendMCPRequest(method string, params interface{}) (map[string]interface{}, error) {
	// Ensure we have a connection
	if c.messageEndpoint == "" {
		if err := c.Connect(); err != nil {
			return nil, fmt.Errorf("failed to connect: %v", err)
		}
	}

	// Send MCP request to the message endpoint
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	msgReq, err := http.NewRequest("POST", c.messageEndpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	msgReq.Header.Set("Content-Type", "application/json")
	msgReq.Header.Set("Authorization", "Bearer "+c.token)

	client := &http.Client{Timeout: 30 * time.Second}
	msgResp, err := client.Do(msgReq)
	if err != nil {
		return nil, err
	}
	defer msgResp.Body.Close()

	respBody, err := io.ReadAll(msgResp.Body)
	if err != nil {
		return nil, err
	}

	if msgResp.StatusCode != 200 && msgResp.StatusCode != 202 {
		return nil, fmt.Errorf("MCP request failed: %d - %s", msgResp.StatusCode, string(respBody))
	}

	// Handle 202 and empty responses - read response from SSE stream
	if msgResp.StatusCode == 202 || len(respBody) == 0 {
		// Read response from SSE stream
		for c.sseScanner.Scan() {
			line := c.sseScanner.Text()

			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				// Try to parse as JSON
				var msg map[string]interface{}
				if err := json.Unmarshal([]byte(data), &msg); err == nil {
					// Check if this is our response (matching ID)
					if id, ok := msg["id"]; ok && id == float64(1) {
						return msg, nil
					}
				}
			}
		}

		if err := c.sseScanner.Err(); err != nil {
			return nil, fmt.Errorf("SSE scanner error: %v", err)
		}

		return nil, fmt.Errorf("no response received from SSE stream")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v - %s", err, string(respBody))
	}

	return result, nil
}

// MockGCPServer provides a mock GCP IAM server for testing
type MockGCPServer struct {
	server *http.Server
	port   string
}

// NewMockGCPServer creates a new mock GCP server
func NewMockGCPServer(port string) *MockGCPServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, fmt.Sprintf("%s?code=test-auth-code&state=%s", redirectURI, state), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"email": "test@test.com",
			"hd":    "test.com",
		})
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	return &MockGCPServer{
		server: server,
		port:   port,
	}
}

// Start starts the mock GCP server
func (m *MockGCPServer) Start() error {
	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

// Stop stops the mock GCP server
func (m *MockGCPServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.server.Shutdown(ctx)
}

// TestEnvironment manages the complete test environment
type TestEnvironment struct {
	dbCmd   *exec.Cmd
	mcpCmd  *exec.Cmd
	mockGCP *MockGCPServer
	client  *MCPClient
}

// SetupTestEnvironment creates and starts all components needed for testing
func SetupTestEnvironment(t *testing.T) *TestEnvironment {
	env := &TestEnvironment{}

	// Start test database
	t.Log("🚀 Starting test database...")
	env.dbCmd = execDockerCompose("-f", "config/docker-compose.test.yml", "up", "-d")
	if err := env.dbCmd.Run(); err != nil {
		t.Fatalf("Failed to start test database: %v", err)
	}

	time.Sleep(10 * time.Second)

	// Start mock GCP server
	t.Log("🚀 Starting mock GCP server...")
	env.mockGCP = NewMockGCPServer("9090")
	if err := env.mockGCP.Start(); err != nil {
		t.Fatalf("Failed to start mock GCP server: %v", err)
	}

	// Start mcp-front
	t.Log("🚀 Starting mcp-front...")
	env.mcpCmd = exec.Command("../mcp-front", "-config", "config/config.test.json")

	// Capture stderr to log file if MCP_LOG_FILE is set
	if logFile := os.Getenv("MCP_LOG_FILE"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			env.mcpCmd.Stderr = f
			env.mcpCmd.Stdout = f
			t.Cleanup(func() { f.Close() })
		}
	}

	if err := env.mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	time.Sleep(15 * time.Second)

	// Create and authenticate client
	env.client = NewMCPClient("http://localhost:8080")
	if err := env.client.Authenticate(); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	return env
}

// Cleanup stops all test environment components
func (env *TestEnvironment) Cleanup() {
	if env.mcpCmd != nil && env.mcpCmd.Process != nil {
		_ = env.mcpCmd.Process.Kill()
	}

	if env.mockGCP != nil {
		_ = env.mockGCP.Stop()
	}

	if env.dbCmd != nil {
		downCmd := execDockerCompose("-f", "config/docker-compose.test.yml", "down", "-v")
		_ = downCmd.Run()
	}
}
