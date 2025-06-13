package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
)

// Server represents the MCP proxy server
type Server struct {
	mux          *http.ServeMux
	config       *config.Config
	oauthServer  *oauth.Server
}

// NewServer creates a new MCP proxy server handler
func NewServer(ctx context.Context, cfg *config.Config) (*Server, error) {
	baseURL, err := url.Parse(cfg.Proxy.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	mux := http.NewServeMux()
	s := &Server{
		mux:    mux,
		config: cfg,
	}
	
	// Build list of allowed CORS origins
	var allowedOrigins []string
	if oauthAuth, ok := cfg.Proxy.Auth.(*config.OAuthAuthConfig); ok && oauthAuth != nil {
		// Use explicitly configured origins if provided
		if len(oauthAuth.AllowedOrigins) > 0 {
			allowedOrigins = oauthAuth.AllowedOrigins
		} else if len(oauthAuth.AllowedDomains) > 0 {
			// Fall back to building from allowed domains for backward compatibility
			internal.LogWarn("Using allowedDomains for CORS is deprecated. Please use allowedOrigins instead.")
			for _, domain := range oauthAuth.AllowedDomains {
				allowedOrigins = append(allowedOrigins, "https://"+domain)
			}
		}
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

		s.oauthServer, err = oauth.NewServer(oauthConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth server: %w", err)
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
		tokenHandlers := NewTokenHandlers(s.oauthServer, cfg.MCPServers)
		tokenMiddlewares := []MiddlewareFunc{
			corsMiddleware(allowedOrigins),
			loggerMiddleware("tokens"),
			s.oauthServer.ValidateTokenMiddleware(),
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
		stdioPath := "/" + serverName + "/stdio"

		internal.LogInfoWithFields("server", "Registering MCP server", map[string]interface{}{
			"name":          serverName,
			"sse_path":      ssePathPrefix,
			"stdio_path":    stdioPath,
			"requires_user_token": serverConfig.RequiresUserToken,
		})

		// Create handler
		var tokenStore oauth.UserTokenStore
		if s.oauthServer != nil {
			tokenStore = s.oauthServer.GetUserTokenStore()
		}
		
		handler := NewMCPHandler(
			serverName,
			serverConfig,
			tokenStore,
			baseURL.String(),
			info,
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

		// Register handler
		mux.Handle(ssePathPrefix, chainMiddleware(handler, middlewares...))
		
		// For backward compatibility, also register without /sse suffix for SSE servers
		if serverConfig.URL != "" {
			ssePath := "/" + serverName
			mux.Handle(ssePath, chainMiddleware(handler, middlewares...))
		}
	}

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	internal.LogInfoWithFields("server", "MCP proxy server initialized", nil)
	return s, nil
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

