package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/mark3labs/mcp-go/mcp"
)

// UserMCPManager manages per-user MCP server instances
type UserMCPManager struct {
	instances map[string]*UserInstance // key: "user@example.com:serverName"
	mu        sync.RWMutex
	timeout   time.Duration
}

// UserInstance represents a user-specific MCP server instance
type UserInstance struct {
	client    *Client
	sseServer *Server  // Complete SSE server (includes MCPServer + SSEServer)
	lastUsed  time.Time
	user      string
	server    string
}

// NewUserMCPManager creates a new manager for user MCP instances
func NewUserMCPManager(timeout time.Duration) *UserMCPManager {
	manager := &UserMCPManager{
		instances: make(map[string]*UserInstance),
		timeout:   timeout,
	}
	manager.startCleanupWorker()
	return manager
}

// startCleanupWorker starts a goroutine that periodically cleans up expired instances
func (m *UserMCPManager) startCleanupWorker() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			m.cleanupExpired()
		}
	}()
}

// cleanupExpired removes instances that haven't been used recently
func (m *UserMCPManager) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, instance := range m.instances {
		if now.Sub(instance.lastUsed) > m.timeout {
			internal.LogInfoWithFields("mcp-manager", "Cleaning up expired instance", map[string]interface{}{
				"user":   instance.user,
				"server": instance.server,
				"age":    now.Sub(instance.lastUsed).String(),
			})
			if instance.client != nil {
				_ = instance.client.Close()
			}
			if instance.sseServer != nil {
				_ = instance.sseServer.Close()
			}
			delete(m.instances, key)
		}
	}
}

// GetOrCreateSSEServer gets an existing SSE server instance or creates a new one
func (m *UserMCPManager) GetOrCreateSSEServer(ctx context.Context, user, serverName string, config *config.MCPClientConfig, userToken string, info mcp.Implementation, setupBaseURL string) (*Server, error) {
	key := fmt.Sprintf("%s:%s", user, serverName)

	// Try to get existing instance
	m.mu.RLock()
	if instance, exists := m.instances[key]; exists {
		instance.lastUsed = time.Now()
		m.mu.RUnlock()
		internal.LogInfoWithFields("mcp-manager", "Reusing existing SSE server", map[string]interface{}{
			"user":   user,
			"server": serverName,
		})
		return instance.sseServer, nil
	}
	m.mu.RUnlock()

	// Create new instance
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if instance, exists := m.instances[key]; exists {
		instance.lastUsed = time.Now()
		return instance.sseServer, nil
	}

	internal.LogInfoWithFields("mcp-manager", "Creating new SSE server instance", map[string]interface{}{
		"user":   user,
		"server": serverName,
	})

	// Create new MCP client with user token
	client, err := createMCPClientWithUserToken(serverName, config, userToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP client: %w", err)
	}

	// Create SSE server
	sseServer := NewMCPServer(serverName, "dev", setupBaseURL, config)
	
	// Connect client to SSE server
	if err := client.AddToMCPServer(ctx, info, sseServer.MCPServer); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to connect client to SSE server: %w", err)
	}

	m.instances[key] = &UserInstance{
		client:    client,
		sseServer: sseServer,
		lastUsed:  time.Now(),
		user:      user,
		server:    serverName,
	}

	return sseServer, nil
}


// CreateStdioInstance creates a fresh instance for stdio servers (one-shot execution)
func (m *UserMCPManager) CreateStdioInstance(ctx context.Context, user, serverName string, config *config.MCPClientConfig, userToken string) (*Client, error) {
	internal.LogInfoWithFields("mcp-manager", "Creating stdio instance", map[string]interface{}{
		"user":   user,
		"server": serverName,
	})

	return createMCPClientWithUserToken(serverName, config, userToken)
}

// createMCPClientWithUserToken creates an MCP client with user token substitution
func createMCPClientWithUserToken(name string, conf *config.MCPClientConfig, userToken string) (*Client, error) {
	// Create a copy of the config to avoid modifying the original
	configCopy := *conf
	
	// Substitute $userToken references in environment variables
	if conf.Env != nil {
		configCopy.Env = make(config.ConfigValueMap)
		for k, v := range conf.Env {
			// Create a new ConfigValue with the resolved token
			resolvedValue := v.ResolveUserToken(userToken)
			configCopy.Env[k] = config.NewConfigValue(resolvedValue)
		}
	}

	// Substitute $userToken in args
	if conf.Args != nil {
		configCopy.Args = make(config.ConfigValueSlice, len(conf.Args))
		for i, v := range conf.Args {
			resolvedValue := v.ResolveUserToken(userToken)
			configCopy.Args[i] = config.NewConfigValue(resolvedValue)
		}
	}

	// Now create the client with substituted values
	return NewMCPClient(name, &configCopy)
}