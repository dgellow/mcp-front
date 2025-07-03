package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/inline"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/services"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Server represents the MCP proxy server
type Server struct {
	mux            *http.ServeMux
	config         *config.Config
	authServer     *auth.Server
	storage        storage.Storage
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
			log.LogInfoWithFields("server", "Using configured session timeout", map[string]any{
				"timeout": sessionTimeout,
			})
		}
		if cfg.Proxy.Sessions.CleanupInterval > 0 {
			cleanupInterval = cfg.Proxy.Sessions.CleanupInterval
			log.LogInfoWithFields("server", "Using configured cleanup interval", map[string]any{
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
		log.LogDebug("initializing OAuth 2.1 server")

		// Parse TTL duration
		ttl, err := time.ParseDuration(oauthAuth.TokenTTL)
		if err != nil {
			return nil, fmt.Errorf("parsing OAuth token TTL: %w", err)
		}

		// Create storage based on configuration
		var store storage.Storage
		if oauthAuth.Storage == "firestore" {
			log.LogInfoWithFields("oauth", "Using Firestore storage", map[string]any{
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
			log.LogInfoWithFields("oauth", "Using in-memory storage", map[string]any{})
			store = storage.NewMemoryStorage()
		}

		authConfig := auth.Config{
			Issuer:              oauthAuth.Issuer,
			TokenTTL:            ttl,
			SessionDuration:     24 * time.Hour, // Default session duration for browser SSO
			AllowedDomains:      oauthAuth.AllowedDomains,
			AllowedOrigins:      oauthAuth.AllowedOrigins,
			GoogleClientID:      oauthAuth.GoogleClientID,
			GoogleClientSecret:  string(oauthAuth.GoogleClientSecret),
			GoogleRedirectURI:   oauthAuth.GoogleRedirectURI,
			JWTSecret:           string(oauthAuth.JWTSecret),
			EncryptionKey:       string(oauthAuth.EncryptionKey),
			StorageType:         oauthAuth.Storage,
			GCPProjectID:        oauthAuth.GCPProject,
			FirestoreDatabase:   oauthAuth.FirestoreDatabase,
			FirestoreCollection: oauthAuth.FirestoreCollection,
		}

		s.authServer, err = auth.NewServer(authConfig, store)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth server: %w", err)
		}

		s.storage = store

		// Initialize admin users if admin is enabled
		if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
			for _, adminEmail := range cfg.Proxy.Admin.AdminEmails {
				// Upsert admin user
				if err := store.UpsertUser(ctx, adminEmail); err != nil {
					log.LogWarnWithFields("server", "Failed to initialize admin user", map[string]any{
						"email": adminEmail,
						"error": err.Error(),
					})
					continue
				}
				// Set as admin
				if err := store.SetUserAdmin(ctx, adminEmail, true); err != nil {
					log.LogWarnWithFields("server", "Failed to set user as admin", map[string]any{
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
			recoverMiddleware("mcp"),
		}

		authHandlers := NewAuthHandlers(s.authServer, cfg.MCPServers)
		mux.Handle("/.well-known/oauth-authorization-server", chainMiddleware(http.HandlerFunc(authHandlers.WellKnownHandler), oauthMiddlewares...))
		mux.Handle("/authorize", chainMiddleware(http.HandlerFunc(authHandlers.AuthorizeHandler), oauthMiddlewares...))
		mux.Handle("/oauth/callback", chainMiddleware(http.HandlerFunc(authHandlers.GoogleCallbackHandler), oauthMiddlewares...))
		mux.Handle("/token", chainMiddleware(http.HandlerFunc(authHandlers.TokenHandler), oauthMiddlewares...))
		mux.Handle("/register", chainMiddleware(http.HandlerFunc(authHandlers.RegisterHandler), oauthMiddlewares...))

		// Protected endpoints - require authentication
		tokenHandlers := NewTokenHandlers(s.storage, cfg.MCPServers, s.authServer != nil)
		tokenMiddlewares := []MiddlewareFunc{
			corsMiddleware(allowedOrigins),
			loggerMiddleware("tokens"),
			s.authServer.SSOMiddleware(),
			recoverMiddleware("mcp"),
		}

		// Token management UI endpoints
		mux.Handle("/my/tokens", chainMiddleware(http.HandlerFunc(tokenHandlers.ListTokensHandler), tokenMiddlewares...))
		mux.Handle("/my/tokens/set", chainMiddleware(http.HandlerFunc(tokenHandlers.SetTokenHandler), tokenMiddlewares...))
		mux.Handle("/my/tokens/delete", chainMiddleware(http.HandlerFunc(tokenHandlers.DeleteTokenHandler), tokenMiddlewares...))

		// OAuth service endpoints
		serviceOAuthClient := services.NewServiceOAuthClient(s.storage, cfg.Proxy.BaseURL)
		serviceAuthHandlers := NewServiceAuthHandlers(serviceOAuthClient, cfg.MCPServers, s.storage)

		// OAuth interstitial page - requires Google authentication
		mux.Handle("/oauth/services", chainMiddleware(http.HandlerFunc(authHandlers.ServiceSelectionHandler), tokenMiddlewares...))

		// OAuth completion endpoint - requires Google authentication
		mux.Handle("/oauth/complete", chainMiddleware(http.HandlerFunc(authHandlers.CompleteOAuthHandler), tokenMiddlewares...))

		// OAuth connect endpoint - requires Google authentication
		mux.Handle("/oauth/connect", chainMiddleware(http.HandlerFunc(serviceAuthHandlers.ConnectHandler), tokenMiddlewares...))

		// OAuth callback endpoints - must be publicly accessible for external OAuth providers
		mux.HandleFunc("/oauth/callback/", serviceAuthHandlers.CallbackHandler)

		// OAuth disconnect endpoint - requires Google authentication
		mux.Handle("/oauth/disconnect", chainMiddleware(http.HandlerFunc(serviceAuthHandlers.DisconnectHandler), tokenMiddlewares...))
	}

	// Setup MCP server endpoints
	for serverName, serverConfig := range cfg.MCPServers {
		// Build path like /notion/sse
		ssePathPrefix := "/" + serverName + "/sse"

		log.LogInfoWithFields("server", "Registering MCP server", map[string]any{
			"name":                serverName,
			"sse_path":            ssePathPrefix,
			"transport_type":      serverConfig.TransportType,
			"requires_user_token": serverConfig.RequiresUserToken,
		})

		var handler http.Handler

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
			handler = inline.NewHandler(serverName, inlineServer)

			log.LogInfoWithFields("server", "Created inline MCP server", map[string]any{
				"name":  serverName,
				"tools": len(resolvedTools),
			})
		} else {

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
						log.LogErrorWithFields("server", "No session handler in context", map[string]any{
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

						if handler.h.storage != nil {
							if err := handler.h.storage.RevokeSession(sessionCtx, session.SessionID()); err != nil {
								log.LogWarnWithFields("server", "Failed to revoke session from storage", map[string]any{
									"error":     err.Error(),
									"sessionID": session.SessionID(),
									"user":      handler.userEmail,
								})
							}
						}

						log.LogInfoWithFields("server", "Session unregistered and cleaned up", map[string]any{
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

			// Create MCP handler for stdio/SSE servers
			handler = NewMCPHandler(
				serverName,
				serverConfig,
				s.storage,
				baseURL.String(),
				info,
				s.sessionManager,
				s.sseServers[serverName], // Pass the shared MCP server (nil for non-stdio)
			)
		}

		// Setup middlewares
		var middlewares []MiddlewareFunc
		middlewares = append(middlewares, loggerMiddleware("mcp"))
		middlewares = append(middlewares, corsMiddleware(allowedOrigins))

		if s.authServer != nil {
			log.LogTraceWithFields("server", "Adding OAuth middleware", map[string]any{
				"server_name": serverName,
			})
			middlewares = append(middlewares, s.authServer.ValidateTokenMiddleware())
		}

		if len(serverConfig.ServiceAuths) > 0 {
			log.LogTraceWithFields("server", "Adding service auth middleware", map[string]any{
				"server_name": serverName,
				"auth_count":  len(serverConfig.ServiceAuths),
			})
			middlewares = append(middlewares, newServiceAuthMiddleware(serverConfig.ServiceAuths))
		}

		// important to be last, making it the outermost middleware, so it can recover from any middleware panic
		middlewares = append(middlewares, recoverMiddleware("mcp"))

		// Register handler - SSE server needs to handle all paths under the server name
		// It handles both /postgres/sse and /postgres/message endpoints
		mux.Handle("/"+serverName+"/", chainMiddleware(handler, middlewares...))
	}

	// Admin routes - only if admin is enabled
	if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
		log.LogInfoWithFields("server", "Admin UI enabled", map[string]any{
			"admin_emails": cfg.Proxy.Admin.AdminEmails,
		})

		// Get encryption key from OAuth config
		var encryptionKey string
		if oauthAuth, ok := cfg.Proxy.Auth.(*config.OAuthAuthConfig); ok && oauthAuth != nil {
			encryptionKey = string(oauthAuth.EncryptionKey)
		}

		adminHandlers := NewAdminHandlers(s.storage, cfg, s.sessionManager, encryptionKey)
		adminMiddlewares := []MiddlewareFunc{
			corsMiddleware(allowedOrigins),
			loggerMiddleware("admin"),
			s.authServer.SSOMiddleware(),                // Browser SSO
			adminMiddleware(cfg.Proxy.Admin, s.storage), // Admin check
			recoverMiddleware("mcp"),
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

	log.LogInfoWithFields("server", "MCP proxy server initialized", nil)
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

// formatUserToken formats a stored token according to the user authentication configuration
func formatUserToken(storedToken *storage.StoredToken, auth *config.UserAuthentication) string {
	if storedToken == nil {
		return ""
	}

	if storedToken.Type == storage.TokenTypeOAuth && storedToken.OAuthData != nil {
		token := storedToken.OAuthData.AccessToken
		if auth.TokenFormat != "" && auth.TokenFormat != "{{token}}" {
			return strings.ReplaceAll(auth.TokenFormat, "{{token}}", token)
		}
		return token
	}

	token := storedToken.Value
	if auth != nil && auth.TokenFormat != "" && auth.TokenFormat != "{{token}}" {
		return strings.ReplaceAll(auth.TokenFormat, "{{token}}", token)
	}
	return token
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

	log.LogDebugWithFields("server", "Registering session", map[string]any{
		"sessionID": session.SessionID(),
		"server":    handler.h.serverName,
		"user":      handler.userEmail,
	})

	log.LogTraceWithFields("server", "Session registration started", map[string]any{
		"sessionID":         session.SessionID(),
		"server":            handler.h.serverName,
		"user":              handler.userEmail,
		"requiresUserToken": handler.config.RequiresUserToken,
		"transportType":     handler.config.TransportType,
		"command":           handler.config.Command,
	})

	var userToken string
	if handler.config.RequiresUserToken && handler.userEmail != "" && handler.h.storage != nil {
		storedToken, err := handler.h.storage.GetUserToken(sessionCtx, handler.userEmail, handler.h.serverName)
		if err != nil {
			log.LogDebugWithFields("server", "No user token found", map[string]any{
				"server": handler.h.serverName,
				"user":   handler.userEmail,
			})
		} else if storedToken != nil {
			if handler.config.UserAuthentication != nil {
				userToken = formatUserToken(storedToken, handler.config.UserAuthentication)
			} else {
				userToken = storedToken.Value
			}
		}
	}

	stdioSession, err := sessionManager.GetOrCreateSession(
		sessionCtx,
		key,
		handler.config,
		handler.h.info,
		handler.h.setupBaseURL,
		userToken,
	)
	if err != nil {
		log.LogErrorWithFields("server", "Failed to create stdio session", map[string]any{
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
		handler.h.storage,
		handler.h.serverName,
		handler.h.setupBaseURL,
		handler.config.UserAuthentication,
		session,
	); err != nil {
		log.LogErrorWithFields("server", "Failed to discover and register capabilities", map[string]any{
			"error":     err.Error(),
			"sessionID": session.SessionID(),
			"server":    handler.h.serverName,
			"user":      handler.userEmail,
		})
		sessionManager.RemoveSession(key)
		return
	}

	if handler.userEmail != "" {
		if handler.h.storage != nil {
			activeSession := storage.ActiveSession{
				SessionID:  session.SessionID(),
				UserEmail:  handler.userEmail,
				ServerName: handler.h.serverName,
				Created:    time.Now(),
				LastActive: time.Now(),
			}
			if err := handler.h.storage.TrackSession(sessionCtx, activeSession); err != nil {
				log.LogWarnWithFields("server", "Failed to track session", map[string]any{
					"error":     err.Error(),
					"sessionID": session.SessionID(),
					"user":      handler.userEmail,
				})
			}
		}
	}

	log.LogInfoWithFields("server", "Session successfully created and connected", map[string]any{
		"sessionID": session.SessionID(),
		"server":    handler.h.serverName,
		"user":      handler.userEmail,
	})
}
