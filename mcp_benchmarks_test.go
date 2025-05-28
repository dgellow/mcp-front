package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func BenchmarkMCPClientCreation(b *testing.B) {
	configs := []*MCPClientConfigV2{
		// Stdio config
		{
			Command: "echo",
			Args:    []string{"hello"},
			Env:     map[string]string{"TEST": "value"},
		},
		// SSE config  
		{
			URL:     "https://example.com/sse",
			Headers: map[string]string{"Authorization": "Bearer token"},
		},
		// Streamable HTTP config
		{
			TransportType: MCPClientTypeStreamable,
			URL:           "https://example.com/stream",
			Headers:       map[string]string{"Authorization": "Bearer token"},
			Timeout:       30 * time.Second,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := configs[i%len(configs)]
		client, err := newMCPClient("test", config)
		if err != nil {
			b.Fatal(err)
		}
		_ = client
	}
}

func BenchmarkMCPServerCreation(b *testing.B) {
	config := &MCPClientConfigV2{
		Command: "echo",
		Args:    []string{"hello"},
		Options: &OptionsV2{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server := newMCPServer("test", "1.0.0", "https://example.com", config)
		_ = server
	}
}

func BenchmarkSSEServerResponse(b *testing.B) {
	// Mock SSE data
	testData := `{"jsonrpc": "2.0", "method": "tools/list", "params": {}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test/sse", nil)
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Cache-Control", "no-cache")
		
		w := httptest.NewRecorder()
		
		// Simulate SSE streaming (without actual MCP client connection)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		
		// Write test SSE data
		w.Write([]byte("data: " + testData + "\n\n"))
		
		if w.Code != http.StatusOK {
			b.Fatalf("Expected 200, got %d", w.Code)
		}
	}
}

func BenchmarkMiddlewareChain(b *testing.B) {
	// Create middleware chain similar to real usage
	middlewares := []MiddlewareFunc{
		recoverMiddleware("test"),
		loggerMiddleware("test"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	chainedHandler := chainMiddleware(handler, middlewares...)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		
		chainedHandler.ServeHTTP(w, req)
		
		if w.Code != http.StatusOK {
			b.Fatalf("Expected 200, got %d", w.Code)
		}
	}
}

func BenchmarkAuthMiddleware(b *testing.B) {
	tokens := []string{"token1", "token2", "token3"}
	authMiddleware := newAuthMiddleware(tokens)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authedHandler := authMiddleware(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer token1")
		w := httptest.NewRecorder()
		
		authedHandler.ServeHTTP(w, req)
		
		if w.Code != http.StatusOK {
			b.Fatalf("Expected 200, got %d", w.Code)
		}
	}
}

func BenchmarkJSONRPCParsing(b *testing.B) {
	// Simulate parsing JSON-RPC messages from MCP servers
	testMessages := []string{
		`{"jsonrpc": "2.0", "method": "tools/list", "params": {}}`,
		`{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "test_tool", "arguments": {"arg1": "value1"}}}`,
		`{"jsonrpc": "2.0", "result": {"tools": [{"name": "test", "description": "A test tool"}]}, "id": 1}`,
		`{"jsonrpc": "2.0", "method": "resources/list", "params": {"cursor": "abc123"}}`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := testMessages[i%len(testMessages)]
		
		// Simulate the JSON parsing that happens in real usage
		var parsed map[string]interface{}
		err := json.Unmarshal([]byte(msg), &parsed)
		if err != nil {
			b.Fatal(err)
		}
		
		// Simulate basic validation
		if _, ok := parsed["jsonrpc"]; !ok {
			b.Fatal("Invalid JSON-RPC")
		}
	}
}

func BenchmarkConfigParsing(b *testing.B) {
	configJSON := `{
		"mcpProxy": {
			"baseURL": "https://test.example.com",
			"addr": ":8080",
			"name": "Test Proxy",
			"version": "1.0.0",
			"options": {
				"logEnabled": true
			}
		},
		"oauth": {
			"issuer": "https://test.example.com",
			"gcp_project": "test-project",
			"allowed_domains": ["example.com"],
			"token_ttl": "1h",
			"storage": "memory",
			"google_client_id": "test-client-id",
			"google_client_secret": "test-client-secret",
			"google_redirect_uri": "https://test.example.com/callback"
		},
		"mcpServers": {
			"test1": {
				"command": "echo",
				"args": ["hello"]
			},
			"test2": {
				"url": "https://example.com/sse"
			},
			"test3": {
				"command": "docker",
				"args": ["run", "--rm", "-i", "nginx"]
			}
		}
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Parse JSON
		var rawConfig map[string]interface{}
		err := json.Unmarshal([]byte(configJSON), &rawConfig)
		if err != nil {
			b.Fatal(err)
		}

		// Basic validation that would happen in real parsing
		if _, ok := rawConfig["mcpProxy"]; !ok {
			b.Fatal("Missing mcpProxy")
		}
		if _, ok := rawConfig["mcpServers"]; !ok {
			b.Fatal("Missing mcpServers")
		}
	}
}

func BenchmarkHTTPRouting(b *testing.B) {
	// Simulate the path-based routing logic
	baseURL := "https://example.com"
	serverNames := []string{"notion", "postgres", "git", "external-api"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := serverNames[i%len(serverNames)]
		
		// Simulate the routing logic from http.go
		mcpRoute := "/" + name + "/"
		if !strings.HasPrefix(mcpRoute, "/") {
			mcpRoute = "/" + mcpRoute
		}
		if !strings.HasSuffix(mcpRoute, "/") {
			mcpRoute += "/"
		}
		
		// Simulate URL construction
		fullURL := baseURL + mcpRoute
		_ = fullURL
	}
}

func BenchmarkStreamingData(b *testing.B) {
	// Benchmark the streaming data handling that would happen in stdio bridge
	testData := []byte(`{"jsonrpc": "2.0", "method": "tools/list", "params": {}}`)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate reading from stdout and writing to SSE
		reader := strings.NewReader(string(testData))
		
		// Read the data (simulating stdout read)
		buffer := make([]byte, len(testData))
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			b.Fatal(err)
		}
		
		// Simulate SSE formatting
		sseData := "data: " + string(buffer[:n]) + "\n\n"
		_ = sseData
	}
}

