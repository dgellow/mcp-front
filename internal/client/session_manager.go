package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/mark3labs/mcp-go/mcp"
)

var (
	// ErrSessionNotFound is returned when a session doesn't exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrUserLimitExceeded is returned when user has too many sessions
	ErrUserLimitExceeded = errors.New("user session limit exceeded")

	// ErrSessionCreationFailed is returned when session creation fails
	ErrSessionCreationFailed = errors.New("failed to create session")
)

// StdioSessionManager manages stdio processes for SSE sessions
type StdioSessionManager struct {
	mu              sync.RWMutex
	sessions        map[SessionKey]*StdioSession
	defaultTimeout  time.Duration
	maxPerUser      int
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	createClient    func(name string, config *config.MCPClientConfig) (*Client, error)
	wg              sync.WaitGroup
}

// SessionKey identifies a unique session
type SessionKey struct {
	UserEmail  string // Empty for servers without requiresUserToken
	ServerName string
	SessionID  string
}

// StdioSession represents an active stdio process session
type StdioSession struct {
	client       *Client
	config       *config.MCPClientConfig
	created      time.Time
	lastAccessed atomic.Pointer[time.Time]
	cancel       context.CancelFunc
	ctx          context.Context
	key          SessionKey
}

// SessionManagerOption configures the session manager
type SessionManagerOption func(*StdioSessionManager)

// WithTimeout sets the session timeout duration
func WithTimeout(timeout time.Duration) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.defaultTimeout = timeout
	}
}

// WithMaxPerUser sets the maximum sessions per user
func WithMaxPerUser(max int) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.maxPerUser = max
	}
}

// WithCleanupInterval sets how often to run cleanup
func WithCleanupInterval(interval time.Duration) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.cleanupInterval = interval
	}
}

// WithClientCreator sets a custom client creator function (for testing)
func WithClientCreator(creator func(name string, config *config.MCPClientConfig) (*Client, error)) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.createClient = creator
	}
}

// NewStdioSessionManager creates a new session manager
func NewStdioSessionManager(opts ...SessionManagerOption) *StdioSessionManager {
	sm := &StdioSessionManager{
		sessions:        make(map[SessionKey]*StdioSession),
		defaultTimeout:  5 * time.Minute,
		maxPerUser:      10,
		cleanupInterval: 1 * time.Minute,
		stopCleanup:     make(chan struct{}),
		createClient:    NewMCPClient,
	}

	for _, opt := range opts {
		opt(sm)
	}

	sm.wg.Add(1)
	go sm.startCleanupRoutine()

	return sm
}

// GetOrCreateSession returns existing session or creates new one
func (sm *StdioSessionManager) GetOrCreateSession(
	ctx context.Context,
	key SessionKey,
	config *config.MCPClientConfig,
	info mcp.Implementation,
	baseURL string,
) (*StdioSession, error) {
	// Try to get existing session first
	if session, ok := sm.GetSession(key); ok {
		return session, nil
	}

	// Check user limits before creating new session
	if err := sm.checkUserLimits(key.UserEmail); err != nil {
		return nil, err
	}

	// Create new session
	return sm.createSession(ctx, key, config, info, baseURL)
}

// GetSession retrieves an existing session
func (sm *StdioSessionManager) GetSession(key SessionKey) (*StdioSession, bool) {
	sm.mu.RLock()
	session, ok := sm.sessions[key]
	sm.mu.RUnlock()

	if ok {
		// Update last accessed time
		now := time.Now()
		session.lastAccessed.Store(&now)

		// Check if process is still alive
		select {
		case <-session.ctx.Done():
			// Process died, remove it
			sm.RemoveSession(key)
			return nil, false
		default:
			return session, true
		}
	}

	// Debug: log all sessions when not found
	sm.mu.RLock()
	internal.LogWarnWithFields("session_manager", "Session not found", map[string]interface{}{
		"looking_for":    key,
		"total_sessions": len(sm.sessions),
	})
	for k := range sm.sessions {
		internal.LogWarnWithFields("session_manager", "Existing session", map[string]interface{}{
			"key": k,
		})
	}
	sm.mu.RUnlock()

	return nil, false
}

// RemoveSession removes a session and cleans up its resources
func (sm *StdioSessionManager) RemoveSession(key SessionKey) {
	sm.mu.Lock()
	session, ok := sm.sessions[key]
	if ok {
		delete(sm.sessions, key)
	}
	sm.mu.Unlock()

	if ok {
		// Cancel context to signal shutdown
		session.cancel()

		// Close the client
		if err := session.client.Close(); err != nil {
			internal.LogErrorWithFields("session_manager", "Failed to close client", map[string]interface{}{
				"error":     err.Error(),
				"sessionID": key.SessionID,
				"server":    key.ServerName,
				"user":      key.UserEmail,
			})
		}

		internal.LogInfoWithFields("session_manager", "Removed session", map[string]interface{}{
			"sessionID": key.SessionID,
			"server":    key.ServerName,
			"user":      key.UserEmail,
		})
	}
}

// Shutdown gracefully shuts down the session manager
func (sm *StdioSessionManager) Shutdown() {
	// Stop cleanup routine
	close(sm.stopCleanup)
	sm.wg.Wait()

	// Remove all sessions
	sm.mu.Lock()
	sessions := make([]*StdioSession, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.mu.Unlock()

	// Clean up all sessions
	for _, session := range sessions {
		sm.RemoveSession(session.key)
	}
}

// GetClient returns the MCP client for this session
func (s *StdioSession) GetClient() *Client {
	return s.client
}

// checkUserLimits verifies user hasn't exceeded session limits
func (sm *StdioSessionManager) checkUserLimits(userEmail string) error {
	if userEmail == "" {
		// No limits for anonymous/non-user-specific servers
		return nil
	}

	count := sm.getUserSessionCount(userEmail)
	if count >= sm.maxPerUser {
		internal.LogWarnWithFields("session_manager", "User session limit exceeded", map[string]interface{}{
			"user":  userEmail,
			"count": count,
			"limit": sm.maxPerUser,
		})
		return fmt.Errorf("%w: user %s has %d sessions (limit: %d)",
			ErrUserLimitExceeded, userEmail, count, sm.maxPerUser)
	}

	return nil
}

// getUserSessionCount counts sessions for a specific user
func (sm *StdioSessionManager) getUserSessionCount(userEmail string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for key := range sm.sessions {
		if key.UserEmail == userEmail {
			count++
		}
	}

	return count
}

// createSession creates a new stdio session
func (sm *StdioSessionManager) createSession(
	ctx context.Context,
	key SessionKey,
	config *config.MCPClientConfig,
	info mcp.Implementation,
	baseURL string,
) (*StdioSession, error) {
	// Create context for this session
	sessionCtx, cancel := context.WithCancel(context.Background())

	// Create MCP client
	client, err := sm.createClient(key.ServerName, config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%w: %v", ErrSessionCreationFailed, err)
	}

	// Create session
	now := time.Now()
	session := &StdioSession{
		client:  client,
		config:  config,
		created: now,
		cancel:  cancel,
		ctx:     sessionCtx,
		key:     key,
	}
	session.lastAccessed.Store(&now)

	// Store session
	sm.mu.Lock()
	sm.sessions[key] = session
	sm.mu.Unlock()

	internal.LogInfoWithFields("session_manager", "Created new session", map[string]interface{}{
		"sessionID": key.SessionID,
		"server":    key.ServerName,
		"user":      key.UserEmail,
	})

	return session, nil
}

// startCleanupRoutine periodically removes timed-out sessions
func (sm *StdioSessionManager) startCleanupRoutine() {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.cleanupTimedOutSessions()
		case <-sm.stopCleanup:
			return
		}
	}
}

// cleanupTimedOutSessions removes sessions that have timed out
func (sm *StdioSessionManager) cleanupTimedOutSessions() {
	now := time.Now()

	// Find timed out sessions
	sm.mu.RLock()
	timedOut := make([]SessionKey, 0)
	for key, session := range sm.sessions {
		lastAccessed := session.lastAccessed.Load()
		if lastAccessed != nil && now.Sub(*lastAccessed) > sm.defaultTimeout {
			timedOut = append(timedOut, key)
		}
	}
	sm.mu.RUnlock()

	// Remove timed out sessions
	for _, key := range timedOut {
		internal.LogInfoWithFields("session_manager", "Removing timed out session", map[string]interface{}{
			"sessionID": key.SessionID,
			"server":    key.ServerName,
			"user":      key.UserEmail,
			"timeout":   sm.defaultTimeout,
		})
		sm.RemoveSession(key)
	}
}
