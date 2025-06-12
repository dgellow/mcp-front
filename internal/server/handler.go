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

	info := mcp.Implementation{
		Name:    cfg.Proxy.Name,
		Version: "dev", // TODO: Pass build version from main
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
			corsMiddleware(),
			loggerMiddleware("oauth"),
		}

		mux.Handle("/.well-known/oauth-authorization-server", chainMiddleware(http.HandlerFunc(s.oauthServer.WellKnownHandler), oauthMiddlewares...))
		mux.Handle("/authorize", chainMiddleware(http.HandlerFunc(s.oauthServer.AuthorizeHandler), oauthMiddlewares...))
		mux.Handle("/oauth/callback", chainMiddleware(http.HandlerFunc(s.oauthServer.GoogleCallbackHandler), oauthMiddlewares...))
		mux.Handle("/token", chainMiddleware(http.HandlerFunc(s.oauthServer.TokenHandler), oauthMiddlewares...))
		mux.Handle("/register", chainMiddleware(http.HandlerFunc(s.oauthServer.RegisterHandler), oauthMiddlewares...))
		mux.Handle("/debug/clients", chainMiddleware(http.HandlerFunc(s.oauthServer.DebugClientsHandler), oauthMiddlewares...))

		// Token management UI endpoints
		tokenHandlers := NewTokenHandlers(s.oauthServer, cfg.MCPServers)
		tokenMiddlewares := []MiddlewareFunc{
			corsMiddleware(),
			loggerMiddleware("tokens"),
			s.oauthServer.ValidateTokenMiddleware(),
		}

		mux.Handle("/my/tokens", chainMiddleware(http.HandlerFunc(tokenHandlers.ListTokensHandler), tokenMiddlewares...))
		mux.Handle("/my/tokens/", http.StripPrefix("/my/tokens/", chainMiddleware(http.HandlerFunc(tokenHandlers.SetTokenHandler), tokenMiddlewares...)))
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
		middlewares = append(middlewares, corsMiddleware())
		middlewares = append(middlewares, loggerMiddleware("mcp"))
		middlewares = append(middlewares, recoverMiddleware("mcp"))

		// Add auth middleware based on configuration
		if s.oauthServer != nil {
			// OAuth authentication
			middlewares = append(middlewares, s.oauthServer.ValidateTokenMiddleware())
		} else if serverConfig.Options != nil && len(serverConfig.Options.AuthTokens) > 0 {
			// Bearer token authentication
			middlewares = append(middlewares, newAuthMiddleware(serverConfig.Options.AuthTokens))
		}

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

