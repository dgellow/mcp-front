package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
)

// Middleware types and functions are defined in server.go

// Server represents the MCP proxy server
type Server struct {
	mux          *http.ServeMux
	config       *config.Config
	oauthServer  *oauth.Server
	userManager  *client.UserMCPManager
}

// NewServer creates a new MCP proxy server handler
func NewServer(ctx context.Context, cfg *config.Config) (*Server, error) {
	baseURL, err := url.Parse(cfg.Proxy.BaseURL.String())
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	mux := http.NewServeMux()
	s := &Server{
		mux:         mux,
		config:      cfg,
		userManager: client.NewUserMCPManager(15 * time.Minute),
	}

	info := mcp.Implementation{
		Name:    cfg.Proxy.Name,
		Version: "dev", // TODO: Pass build version from main
	}

	// Initialize OAuth server if OAuth config is provided
	if oauthAuth, ok := cfg.Proxy.Auth.(*config.OAuthAuthConfig); ok && oauthAuth != nil {
		internal.LogDebug("initializing OAuth 2.1 server")

		// Validate required OAuth fields
		if oauthAuth.Issuer == nil || oauthAuth.TokenTTL == "" {
			return nil, fmt.Errorf("OAuth configuration missing required fields: issuer and token_ttl are required")
		}

		ttl, err := time.ParseDuration(oauthAuth.TokenTTL)
		if err != nil {
			return nil, fmt.Errorf("parsing OAuth token TTL: %w", err)
		}

		oauthConfig := oauth.Config{
			Issuer:              oauthAuth.Issuer.String(),
			TokenTTL:            ttl,
			AllowedDomains:      oauthAuth.AllowedDomains,
			GoogleClientID:      oauthAuth.GoogleClientID.String(),
			GoogleClientSecret:  oauthAuth.GoogleClientSecret.String(),
			GoogleRedirectURI:   oauthAuth.GoogleRedirectURI.String(),
			JWTSecret:           oauthAuth.JWTSecret.String(),
			EncryptionKey:       oauthAuth.EncryptionKey.String(),
			StorageType:         oauthAuth.Storage,
			GCPProjectID:        oauthAuth.GCPProject.String(),
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
		mux.HandleFunc("/my/tokens/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/delete") {
				chainMiddleware(http.HandlerFunc(tokenHandlers.DeleteTokenHandler), tokenMiddlewares...).ServeHTTP(w, r)
			} else {
				chainMiddleware(http.HandlerFunc(tokenHandlers.SetTokenHandler), tokenMiddlewares...).ServeHTTP(w, r)
			}
		})

		internal.LogInfoWithFields("oauth", "OAuth 2.1 server initialized", map[string]interface{}{
			"issuer": oauthAuth.Issuer.String(),
		})
	}

	// Add health check endpoint
	mux.Handle("/health", chainMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"mcp-front"}`))
	}), loggerMiddleware("health")))

	// Register MCP server endpoints
	for name, clientConfig := range cfg.MCPServers {
		// Create handler for this MCP server
		handler := NewMCPHandler(
			name,
			clientConfig,
			s.userManager,
			s.oauthServer,
			cfg.Proxy.BaseURL.String(),
			info,
		)

		// Set up middleware chain
		middlewares := make([]MiddlewareFunc, 0)
		middlewares = append(middlewares, corsMiddleware())
		middlewares = append(middlewares, recoverMiddleware(name))
		middlewares = append(middlewares, loggerMiddleware(name))

		// Add authentication middleware
		if s.oauthServer != nil {
			middlewares = append(middlewares, s.oauthServer.ValidateTokenMiddleware())
		} else if clientConfig.Options != nil && len(clientConfig.Options.AuthTokens) > 0 {
			middlewares = append(middlewares, newAuthMiddleware(clientConfig.Options.AuthTokens))
		}

		// Build route path
		mcpRoute := path.Join(baseURL.Path, name)
		if !strings.HasPrefix(mcpRoute, "/") {
			mcpRoute = "/" + mcpRoute
		}
		if !strings.HasSuffix(mcpRoute, "/") {
			mcpRoute += "/"
		}

		internal.LogTraceWithFields(name, "registering route", map[string]interface{}{
			"route":               mcpRoute,
			"middleware_count":    len(middlewares),
			"requires_user_token": clientConfig.RequiresUserToken,
		})
		
		// Register the handler with middleware chain
		mux.Handle(mcpRoute, chainMiddleware(handler, middlewares...))
	}

	return s, nil
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}