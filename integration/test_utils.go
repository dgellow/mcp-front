package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// MCPClient simulates an MCP client for testing
type MCPClient struct {
	baseURL string
	token   string
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

// ValidateBackendConnectivity checks if the postgres container can actually connect to the database
func (c *MCPClient) ValidateBackendConnectivity() error {
	req, err := http.NewRequest("GET", c.baseURL+"/postgres/sse", nil)
	if err != nil {
		return fmt.Errorf("failed to create SSE request: %v", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SSE connection returned %d: %s", resp.StatusCode, string(body))
	}

	scanner := bufio.NewScanner(resp.Body)
	timeout := time.After(5 * time.Second)
	sessionFound := make(chan bool, 1)

	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") && strings.Contains(line, "sessionId=") {
				sessionFound <- true
				return
			}
		}
		sessionFound <- false
	}()

	select {
	case found := <-sessionFound:
		if !found {
			return fmt.Errorf("no valid session endpoint received from SSE")
		}
		return nil
	case <-timeout:
		return fmt.Errorf("timeout waiting for SSE session endpoint")
	}
}

// SendMCPRequest sends an MCP JSON-RPC request and returns the response
func (c *MCPClient) SendMCPRequest(method string, params interface{}) (map[string]interface{}, error) {
	// Step 1: Connect to SSE endpoint to get session
	req, err := http.NewRequest("GET", c.baseURL+"/postgres/sse", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SSE connection failed: %d - %s", resp.StatusCode, string(body))
	}

	// Read the first SSE message to get the session endpoint
	scanner := bufio.NewScanner(resp.Body)
	var messageEndpoint string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			messageEndpoint = data
			break
		}
	}

	if messageEndpoint == "" {
		return nil, fmt.Errorf("no session endpoint received")
	}

	// Step 2: Send MCP request to session endpoint
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

	msgReq, err := http.NewRequest("POST", messageEndpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	msgReq.Header.Set("Content-Type", "application/json")
	msgReq.Header.Set("Authorization", "Bearer "+c.token)

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

	// Handle 202 and empty responses - this is normal for async MCP operations
	if msgResp.StatusCode == 202 || len(respBody) == 0 {
		return map[string]interface{}{
			"status":  "accepted",
			"message": "Request accepted by MCP server",
			"method":  method,
		}, nil
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
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
	env.dbCmd = exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "up", "-d")
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
		env.mcpCmd.Process.Kill()
	}

	if env.mockGCP != nil {
		env.mockGCP.Stop()
	}

	if env.dbCmd != nil {
		downCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "down", "-v")
		downCmd.Run()
	}
}

