package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/inline"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Server represents the MCP proxy server
type Server struct {
	mux            *http.ServeMux
	config         *config.Config
	oauthServer    *oauth.Server
	tokenStore     storage.UserTokenStore
	sessionManager *client.StdioSessionManager
	sseServers     map[string]*server.SSEServer // serverName -> SSE server for stdio servers
}

// NewServer creates a new MCP proxy server handler
func NewServer(ctx context.Context, cfg *config.Config) (*Server, error) {
	baseURL, err := url.Parse(cfg.Proxy.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	mux := http.NewServeMux()

	// Create session manager for stdio servers with configurable timeouts
	sessionTimeout := 5 * time.Minute
	cleanupInterval := 1 * time.Minute
	maxPerUser := 10

	// Use config values if available
	if cfg.Proxy.Sessions != nil {
		if cfg.Proxy.Sessions.Timeout > 0 {
			sessionTimeout = cfg.Proxy.Sessions.Timeout
			internal.LogInfoWithFields("server", "Using configured session timeout", map[string]interface{}{
				"timeout": sessionTimeout,
			})
		}
		if cfg.Proxy.Sessions.CleanupInterval > 0 {
			cleanupInterval = cfg.Proxy.Sessions.CleanupInterval
			internal.LogInfoWithFields("server", "Using configured cleanup interval", map[string]interface{}{
				"interval": cleanupInterval,
			})
		}
		maxPerUser = cfg.Proxy.Sessions.MaxPerUser
	}

	sessionManager := client.NewStdioSessionManager(
		client.WithTimeout(sessionTimeout),
		client.WithMaxPerUser(maxPerUser),
		client.WithCleanupInterval(cleanupInterval),
	)

	s := &Server{
		mux:            mux,
		config:         cfg,
		sessionManager: sessionManager,
		sseServers:     make(map[string]*server.SSEServer),
	}

	// Build list of allowed CORS origins
	var allowedOrigins []string
	if oauthAuth, ok := cfg.Proxy.Auth.(*config.OAuthAuthConfig); ok && oauthAuth != nil {
		allowedOrigins = oauthAuth.AllowedOrigins
	}

	info := mcp.Implementation{
		Name:    cfg.Proxy.Name,
		Version: "dev",
	}

	// Initialize OAuth server if OAuth config is provided
	if oauthAuth, ok := cfg.Proxy.Auth.(*config.OAuthAuthConfig); ok && oauthAuth != nil {
		internal.LogDebug("initializing OAuth 2.1 server")

		// Parse TTL duration
		ttl, err := time.ParseDuration(oauthAuth.TokenTTL)
		if err != nil {
			return nil, fmt.Errorf("parsing OAuth token TTL: %w", err)
		}

		// Create storage based on configuration
		var store storage.Storage
		if oauthAuth.Storage == "firestore" {
			internal.LogInfoWithFields("oauth", "Using Firestore storage", map[string]interface{}{
				"project":    oauthAuth.GCPProject,
				"database":   oauthAuth.FirestoreDatabase,
				"collection": oauthAuth.FirestoreCollection,
			})
			// Create encryptor for Firestore storage
			encryptor, err := crypto.NewEncryptor([]byte(oauthAuth.EncryptionKey))
			if err != nil {
				return nil, fmt.Errorf("failed to create encryptor: %w", err)
			}
			firestoreStorage, err := storage.NewFirestoreStorage(
				ctx,
				oauthAuth.GCPProject,
				oauthAuth.FirestoreDatabase,
				oauthAuth.FirestoreCollection,
				encryptor,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create Firestore storage: %w", err)
			}
			store = firestoreStorage
		} else {
			internal.LogInfoWithFields("oauth", "Using in-memory storage", map[string]interface{}{})
			store = storage.NewMemoryStorage()
		}

		oauthConfig := oauth.Config{
			Issuer:              oauthAuth.Issuer,
			TokenTTL:            ttl,
			AllowedDomains:      oauthAuth.AllowedDomains,
			AllowedOrigins:      oauthAuth.AllowedOrigins,
			GoogleClientID:      oauthAuth.GoogleClientID,
			GoogleClientSecret:  oauthAuth.GoogleClientSecret,
			GoogleRedirectURI:   oauthAuth.GoogleRedirectURI,
			JWTSecret:           oauthAuth.JWTSecret,
			EncryptionKey:       oauthAuth.EncryptionKey,
			StorageType:         oauthAuth.Storage,
			GCPProjectID:        oauthAuth.GCPProject,
			FirestoreDatabase:   oauthAuth.FirestoreDatabase,
			FirestoreCollection: oauthAuth.FirestoreCollection,
		}

		s.oauthServer, err = oauth.NewServer(oauthConfig, store)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth server: %w", err)
		}

		// Use the storage directly as token store
		s.tokenStore = store

		// Initialize admin users if admin is enabled
		if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
			for _, adminEmail := range cfg.Proxy.Admin.AdminEmails {
				// Upsert admin user
				if err := store.UpsertUser(ctx, adminEmail); err != nil {
					internal.LogWarnWithFields("server", "Failed to initialize admin user", map[string]interface{}{
						"email": adminEmail,
						"error": err.Error(),
					})
					continue
				}
				// Set as admin
				if err := store.SetUserAdmin(ctx, adminEmail, true); err != nil {
					internal.LogWarnWithFields("server", "Failed to set user as admin", map[string]interface{}{
						"email": adminEmail,
						"error": err.Error(),
					})
				}
			}
		}

		// Register OAuth endpoints
		oauthMiddlewares := []MiddlewareFunc{
			corsMiddleware(allowedOrigins),
			loggerMiddleware("oauth"),
		}

		mux.Handle("/.well-known/oauth-authorization-server", chainMiddleware(http.HandlerFunc(s.oauthServer.WellKnownHandler), oauthMiddlewares...))
		mux.Handle("/authorize", chainMiddleware(http.HandlerFunc(s.oauthServer.AuthorizeHandler), oauthMiddlewares...))
		mux.Handle("/oauth/callback", chainMiddleware(http.HandlerFunc(s.oauthServer.GoogleCallbackHandler), oauthMiddlewares...))
		mux.Handle("/token", chainMiddleware(http.HandlerFunc(s.oauthServer.TokenHandler), oauthMiddlewares...))
		mux.Handle("/register", chainMiddleware(http.HandlerFunc(s.oauthServer.RegisterHandler), oauthMiddlewares...))

		// Protected endpoints - require authentication
		tokenHandlers := NewTokenHandlers(s.tokenStore, cfg.MCPServers, s.oauthServer != nil)
		tokenMiddlewares := []MiddlewareFunc{
			corsMiddleware(allowedOrigins),
			loggerMiddleware("tokens"),
			s.oauthServer.SSOMiddleware(),
		}

		// Token management UI endpoints
		mux.Handle("/my/tokens", chainMiddleware(http.HandlerFunc(tokenHandlers.ListTokensHandler), tokenMiddlewares...))
		mux.Handle("/my/tokens/set", chainMiddleware(http.HandlerFunc(tokenHandlers.SetTokenHandler), tokenMiddlewares...))
		mux.Handle("/my/tokens/delete", chainMiddleware(http.HandlerFunc(tokenHandlers.DeleteTokenHandler), tokenMiddlewares...))
	}

	// Setup MCP server endpoints
	for serverName, serverConfig := range cfg.MCPServers {
		// Build path like /notion/sse
		ssePathPrefix := "/" + serverName + "/sse"

		internal.LogInfoWithFields("server", "Registering MCP server", map[string]interface{}{
			"name":                serverName,
			"sse_path":            ssePathPrefix,
			"transport_type":      serverConfig.TransportType,
			"requires_user_token": serverConfig.RequiresUserToken,
		})

		// For inline servers, create a custom handler
		if serverConfig.TransportType == config.MCPClientTypeInline {
			// Resolve inline config
			inlineConfig, resolvedTools, err := inline.ResolveConfig(serverConfig.InlineConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve inline config for %s: %w", serverName, err)
			}

			// Create inline server
			inlineServer := inline.NewServer(serverName, inlineConfig, resolvedTools)

			// Create inline handler
			inlineHandler := inline.NewHandler(serverName, inlineServer)

			// Register with standard middlewares
			var middlewares []MiddlewareFunc
			middlewares = append(middlewares, corsMiddleware(allowedOrigins))
			middlewares = append(middlewares, loggerMiddleware("mcp"))
			middlewares = append(middlewares, recoverMiddleware("mcp"))

			// Add auth middleware if configured
			if s.oauthServer != nil {
				middlewares = append(middlewares, s.oauthServer.ValidateTokenMiddleware())
			}

			// Register handler for both /name/sse and /name/message
			mux.Handle("/"+serverName+"/", chainMiddleware(inlineHandler, middlewares...))

			internal.LogInfoWithFields("server", "Registered inline MCP server", map[string]interface{}{
				"name":  serverName,
				"tools": len(resolvedTools),
			})

			continue // Skip the rest of the loop
		}

		// For stdio servers, create a single shared MCP server
		if isStdioServer(serverConfig) {
			// Create the shared MCP server for this stdio server
			// We need to create it first so we can reference it in the hooks
			var mcpServer *server.MCPServer

			// Create hooks for session management
			hooks := &server.Hooks{}

			// Store reference to server name for use in hooks
			currentServerName := serverName

			// Setup hooks that will be called when sessions are created/destroyed
			hooks.AddOnRegisterSession(func(sessionCtx context.Context, session server.ClientSession) {
				// Extract handler from context
				if handler, ok := sessionCtx.Value(sessionHandlerKey{}).(*sessionRequestHandler); ok {
					// Pass the MCP server to the handler
					handler.mcpServer = mcpServer
					// Handle session registration
					handleSessionRegistration(sessionCtx, session, handler, s.sessionManager)
				} else {
					internal.LogErrorWithFields("server", "No session handler in context", map[string]interface{}{
						"sessionID": session.SessionID(),
						"server":    currentServerName,
					})
				}
			})

			hooks.AddOnUnregisterSession(func(sessionCtx context.Context, session server.ClientSession) {
				// Extract handler from context
				if handler, ok := sessionCtx.Value(sessionHandlerKey{}).(*sessionRequestHandler); ok {
					// Handle session cleanup
					key := client.SessionKey{
						UserEmail:  handler.userEmail,
						ServerName: handler.h.serverName,
						SessionID:  session.SessionID(),
					}
					s.sessionManager.RemoveSession(key)

					// Remove session from storage
					if store, ok := handler.h.tokenStore.(storage.Storage); ok {
						if err := store.RevokeSession(sessionCtx, session.SessionID()); err != nil {
							internal.LogWarnWithFields("server", "Failed to revoke session from storage", map[string]interface{}{
								"error":     err.Error(),
								"sessionID": session.SessionID(),
								"user":      handler.userEmail,
							})
						}
					}

					internal.LogInfoWithFields("server", "Session unregistered and cleaned up", map[string]interface{}{
						"sessionID": session.SessionID(),
						"server":    currentServerName,
						"user":      handler.userEmail,
					})
				}
			})

			// Now create the MCP server with the hooks
			mcpServer = server.NewMCPServer(serverName, "1.0.0",
				server.WithHooks(hooks),
				server.WithPromptCapabilities(true),
				server.WithResourceCapabilities(true, true),
				server.WithToolCapabilities(true),
				server.WithLogging(),
			)

			// Create the SSE server wrapper around the MCP server
			sseServer := server.NewSSEServer(mcpServer,
				server.WithStaticBasePath(serverName),
				server.WithBaseURL(baseURL.String()),
			)

			s.sseServers[serverName] = sseServer
		}

		// Create handler
		handler := NewMCPHandler(
			serverName,
			serverConfig,
			s.tokenStore,
			baseURL.String(),
			info,
			s.sessionManager,
			s.sseServers[serverName], // Pass the shared MCP server (nil for non-stdio)
		)

		// Setup middlewares
		var middlewares []MiddlewareFunc
		middlewares = append(middlewares, corsMiddleware(allowedOrigins))
		middlewares = append(middlewares, loggerMiddleware("mcp"))
		middlewares = append(middlewares, recoverMiddleware("mcp"))

		// Add auth middleware based on configuration
		// Auth models:
		// 1. OAuth: If OAuth server is configured, ALL MCP endpoints require OAuth authentication
		// 2. Bearer token: Individual MCP servers can require bearer tokens (per-server auth)
		// 3. No auth: If neither OAuth nor bearer tokens configured, endpoint is public
		if s.oauthServer != nil {
			// OAuth authentication - user must be authenticated via Google OAuth
			middlewares = append(middlewares, s.oauthServer.ValidateTokenMiddleware())
		} else if serverConfig.Options != nil && len(serverConfig.Options.AuthTokens) > 0 {
			// Bearer token authentication - request must include valid bearer token
			middlewares = append(middlewares, newAuthMiddleware(serverConfig.Options.AuthTokens))
		}
		// else: no auth required for this endpoint

		// Register handler - SSE server needs to handle all paths under the server name
		// It handles both /postgres/sse and /postgres/message endpoints
		mux.Handle("/"+serverName+"/", chainMiddleware(handler, middlewares...))

		// For backward compatibility, also register without /sse suffix for SSE servers
		if serverConfig.URL != "" {
			ssePath := "/" + serverName
			mux.Handle(ssePath, chainMiddleware(handler, middlewares...))
		}
	}

	// Admin routes - only if admin is enabled
	if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
		internal.LogInfoWithFields("server", "Admin UI enabled", map[string]interface{}{
			"admin_emails": cfg.Proxy.Admin.AdminEmails,
		})

		// Get encryption key from OAuth config
		var encryptionKey string
		if oauthAuth, ok := cfg.Proxy.Auth.(*config.OAuthAuthConfig); ok && oauthAuth != nil {
			encryptionKey = oauthAuth.EncryptionKey
		}

		adminHandlers := NewAdminHandlers(s.tokenStore.(storage.Storage), cfg, s.sessionManager, encryptionKey)
		adminMiddlewares := []MiddlewareFunc{
			corsMiddleware(allowedOrigins),
			loggerMiddleware("admin"),
			s.oauthServer.SSOMiddleware(),                                    // Browser SSO
			adminMiddleware(cfg.Proxy.Admin, s.tokenStore.(storage.Storage)), // Admin check
		}

		// Admin routes - all protected by admin middleware
		mux.Handle("/admin", chainMiddleware(http.HandlerFunc(adminHandlers.DashboardHandler), adminMiddlewares...))
		mux.Handle("/admin/users", chainMiddleware(http.HandlerFunc(adminHandlers.UserActionHandler), adminMiddlewares...))
		mux.Handle("/admin/sessions", chainMiddleware(http.HandlerFunc(adminHandlers.SessionActionHandler), adminMiddlewares...))
		mux.Handle("/admin/logging", chainMiddleware(http.HandlerFunc(adminHandlers.LoggingActionHandler), adminMiddlewares...))
	}

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	internal.LogInfoWithFields("server", "MCP proxy server initialized", nil)
	return s, nil
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	if s.sessionManager != nil {
		s.sessionManager.Shutdown()
	}
	return nil
}

// isStdioServer checks if this is a stdio-based server
func isStdioServer(config *config.MCPClientConfig) bool {
	return config.Command != ""
}

// sessionHandlerKey is the context key for session handlers
type sessionHandlerKey struct{}

// sessionRequestHandler handles session-specific logic for a request
type sessionRequestHandler struct {
	h         *MCPHandler
	userEmail string
	config    *config.MCPClientConfig
	mcpServer *server.MCPServer // The shared MCP server
}

// handleSessionRegistration handles the registration of a new session
func handleSessionRegistration(
	sessionCtx context.Context,
	session server.ClientSession,
	handler *sessionRequestHandler,
	sessionManager *client.StdioSessionManager,
) {
	// Create stdio process for this session
	key := client.SessionKey{
		UserEmail:  handler.userEmail,
		ServerName: handler.h.serverName,
		SessionID:  session.SessionID(),
	}

	internal.LogDebugWithFields("server", "Registering session", map[string]interface{}{
		"sessionID": session.SessionID(),
		"server":    handler.h.serverName,
		"user":      handler.userEmail,
	})

	internal.LogTraceWithFields("server", "Session registration started", map[string]interface{}{
		"sessionID":         session.SessionID(),
		"server":            handler.h.serverName,
		"user":              handler.userEmail,
		"requiresUserToken": handler.config.RequiresUserToken,
		"transportType":     handler.config.TransportType,
		"command":           handler.config.Command,
	})

	stdioSession, err := sessionManager.GetOrCreateSession(
		sessionCtx,
		key,
		handler.config,
		handler.h.info,
		handler.h.setupBaseURL,
	)
	if err != nil {
		internal.LogErrorWithFields("server", "Failed to create stdio session", map[string]interface{}{
			"error":     err.Error(),
			"sessionID": session.SessionID(),
			"server":    handler.h.serverName,
			"user":      handler.userEmail,
		})
		return
	}

	// Discover and register capabilities from the stdio process
	if err := stdioSession.DiscoverAndRegisterCapabilities(
		sessionCtx,
		handler.mcpServer,
		handler.userEmail,
		handler.config.RequiresUserToken,
		handler.h.tokenStore,
		handler.h.serverName,
		handler.h.setupBaseURL,
		handler.config.TokenSetup,
		session,
	); err != nil {
		internal.LogErrorWithFields("server", "Failed to discover and register capabilities", map[string]interface{}{
			"error":     err.Error(),
			"sessionID": session.SessionID(),
			"server":    handler.h.serverName,
			"user":      handler.userEmail,
		})
		sessionManager.RemoveSession(key)
		return
	}

	if handler.userEmail != "" {
		if store, ok := handler.h.tokenStore.(storage.Storage); ok {
			activeSession := storage.ActiveSession{
				SessionID:  session.SessionID(),
				UserEmail:  handler.userEmail,
				ServerName: handler.h.serverName,
				Created:    time.Now(),
				LastActive: time.Now(),
			}
			if err := store.TrackSession(sessionCtx, activeSession); err != nil {
				internal.LogWarnWithFields("server", "Failed to track session", map[string]interface{}{
					"error":     err.Error(),
					"sessionID": session.SessionID(),
					"user":      handler.userEmail,
				})
			}
		}
	}

	internal.LogInfoWithFields("server", "Session successfully created and connected", map[string]interface{}{
		"sessionID": session.SessionID(),
		"server":    handler.h.serverName,
		"user":      handler.userEmail,
	})
}
