package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"

	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sync/errgroup"
)

type MiddlewareFunc func(http.Handler) http.Handler

func chainMiddleware(h http.Handler, middlewares ...MiddlewareFunc) http.Handler {
	for _, mw := range middlewares {
		h = mw(h)
	}
	return h
}

func corsMiddleware() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				origin = "*"
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control, mcp-protocol-version")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "3600")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter captures response status and size
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w}
}

func (rw *responseWriter) Status() int {
	if !rw.wrote {
		return http.StatusOK
	}
	return rw.status
}

func (rw *responseWriter) BytesWritten() int {
	return rw.bytes
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wrote {
		rw.status = code
		rw.wrote = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wrote {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

func newAuthMiddleware(tokens []string) MiddlewareFunc {
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(tokens) != 0 {
				authHeader := r.Header.Get("Authorization")

				// RFC 6750: Bearer token must start with "Bearer " followed by exactly one space
				if !strings.HasPrefix(authHeader, "Bearer ") {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				// Extract token after "Bearer " (7 characters)
				token := authHeader[7:]

				// Token must not be empty and must not contain leading/trailing spaces
				if token == "" || strings.TrimSpace(token) != token {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				if _, ok := tokenSet[token]; !ok {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func loggerMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := wrapResponseWriter(w)
			
			next.ServeHTTP(wrapped, r)
			
			// Log request with response details
			internal.LogInfoWithFields(prefix, "request", map[string]interface{}{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      wrapped.Status(),
				"duration_ms": time.Since(start).Milliseconds(),
				"bytes":       wrapped.BytesWritten(),
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
			})
		})
	}
}

func recoverMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					internal.Logf("<%s> Recovered from panic: %v", prefix, err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Start starts the HTTP server with the given configuration
func Start(cfg *config.Config) error {
	baseURL, err := url.Parse(fmt.Sprintf("%v", cfg.Proxy.BaseURL))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var errorGroup errgroup.Group
	httpMux := http.NewServeMux()
	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%v", cfg.Proxy.Addr),
		Handler: httpMux,
	}
	info := mcp.Implementation{
		Name:    cfg.Proxy.Name,
		Version: "dev", // TODO: Pass build version from main
	}

	// Initialize OAuth server if OAuth config is provided
	var oauthServer *oauth.Server
	if oauthAuth, ok := cfg.Proxy.Auth.(*config.OAuthAuthConfig); ok && oauthAuth != nil {
		internal.LogDebug("initializing OAuth 2.1 server")

		// Validate required OAuth fields
		if oauthAuth.Issuer == nil || oauthAuth.TokenTTL == "" {
			internal.LogError("OAuth configuration missing required fields: issuer and token_ttl are required")
			return fmt.Errorf("OAuth configuration missing required fields: issuer and token_ttl are required")
		}

		internal.LogDebug("parsing OAuth token TTL: %s", oauthAuth.TokenTTL)
		ttl, err := time.ParseDuration(oauthAuth.TokenTTL)
		if err != nil {
			internal.LogError("failed to parse OAuth token TTL '%s': %v", oauthAuth.TokenTTL, err)
			return fmt.Errorf("parsing OAuth token TTL: %w", err)
		}

		oauthConfig := oauth.Config{
			Issuer:              fmt.Sprintf("%v", oauthAuth.Issuer),
			TokenTTL:            ttl,
			AllowedDomains:      oauthAuth.AllowedDomains,
			GoogleClientID:      fmt.Sprintf("%v", oauthAuth.GoogleClientID),
			GoogleClientSecret:  fmt.Sprintf("%v", oauthAuth.GoogleClientSecret),
			GoogleRedirectURI:   fmt.Sprintf("%v", oauthAuth.GoogleRedirectURI),
			JWTSecret:           fmt.Sprintf("%v", oauthAuth.JWTSecret),
			StorageType:         oauthAuth.Storage,
			GCPProjectID:        fmt.Sprintf("%v", oauthAuth.GCPProject),
			FirestoreDatabase:   oauthAuth.FirestoreDatabase,
			FirestoreCollection: oauthAuth.FirestoreCollection,
		}

		internal.LogTraceWithFields("oauth", "creating OAuth server", map[string]interface{}{
			"issuer":          oauthConfig.Issuer,
			"token_ttl":       oauthConfig.TokenTTL.String(),
			"allowed_domains": oauthConfig.AllowedDomains,
		})

		oauthServer, err = oauth.NewServer(oauthConfig)
		if err != nil {
			internal.LogErrorWithFields("oauth", "failed to create OAuth server", map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to create OAuth server: %w", err)
		}

		if oauthServer == nil {
			internal.LogErrorWithFields("oauth", "OAuth server creation returned nil", nil)
			return fmt.Errorf("OAuth server creation returned nil")
		}

		internal.LogTraceWithFields("oauth", "registering OAuth endpoints", map[string]interface{}{
			"endpoints": []string{
				"/.well-known/oauth-authorization-server",
				"/authorize",
				"/oauth/callback",
				"/token",
				"/register",
				"/debug/clients",
			},
		})

		// Register OAuth endpoints with CORS and logging middleware
		oauthMiddlewares := []MiddlewareFunc{
			corsMiddleware(),
			loggerMiddleware("oauth"),
		}
		
		httpMux.Handle("/.well-known/oauth-authorization-server", chainMiddleware(http.HandlerFunc(oauthServer.WellKnownHandler), oauthMiddlewares...))
		httpMux.Handle("/authorize", chainMiddleware(http.HandlerFunc(oauthServer.AuthorizeHandler), oauthMiddlewares...))
		httpMux.Handle("/oauth/callback", chainMiddleware(http.HandlerFunc(oauthServer.GoogleCallbackHandler), oauthMiddlewares...))
		httpMux.Handle("/token", chainMiddleware(http.HandlerFunc(oauthServer.TokenHandler), oauthMiddlewares...))
		httpMux.Handle("/register", chainMiddleware(http.HandlerFunc(oauthServer.RegisterHandler), oauthMiddlewares...))

		// Debug endpoint to see registered clients
		httpMux.Handle("/debug/clients", chainMiddleware(http.HandlerFunc(oauthServer.DebugClientsHandler), oauthMiddlewares...))

		internal.LogInfoWithFields("oauth", "OAuth 2.1 server initialized", map[string]interface{}{
			"issuer": oauthAuth.Issuer,
		})
	} else {
		internal.LogDebug("no OAuth configuration found, using token-based authentication")
	}

	// Add health check endpoint with logging
	httpMux.Handle("/health", chainMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"mcp-front"}`))
	}), loggerMiddleware("health")))

	for name, clientConfig := range cfg.MCPServers {
		mcpClient, err := client.NewMCPClient(name, clientConfig)
		if err != nil {
			internal.Logf("<%s> Failed to create client: %v", name, err)
			os.Exit(1)
		}
		server := client.NewMCPServer(name, "dev", fmt.Sprintf("%v", cfg.Proxy.BaseURL), clientConfig)

		// Capture loop variables to avoid closure issues
		currentName := name
		currentClient := mcpClient
		currentServer := server
		currentConfig := clientConfig

		errorGroup.Go(func() error {
			internal.LogTraceWithFields(currentName, "starting MCP client initialization", nil)

			// Add nil checks to prevent panics
			if currentClient == nil {
				internal.LogErrorWithFields(currentName, "client is nil", nil)
				return fmt.Errorf("<%s> client is nil", currentName)
			}
			if currentServer == nil || currentServer.MCPServer == nil {
				internal.LogErrorWithFields(currentName, "server or mcpServer is nil", nil)
				return fmt.Errorf("<%s> server or mcpServer is nil", currentName)
			}

			internal.LogTraceWithFields(currentName, "client and server objects validated", nil)
			internal.LogInfoWithFields(currentName, "connecting to MCP server", nil)
			addErr := currentClient.AddToMCPServer(ctx, info, currentServer.MCPServer)
			if addErr != nil {
				internal.LogErrorWithFields(currentName, "failed to add client to server", map[string]interface{}{
					"error": addErr.Error(),
				})
				if currentConfig != nil && currentConfig.Options != nil && config.BoolOrDefault(currentConfig.Options.PanicIfInvalid, false) {
					return addErr
				}
				return nil
			}
			internal.LogInfoWithFields(currentName, "connected to MCP server", nil)

			internal.LogTraceWithFields(currentName, "setting up middleware chain", nil)
			middlewares := make([]MiddlewareFunc, 0)

			// Add CORS as the FIRST middleware to handle OPTIONS before auth
			middlewares = append(middlewares, corsMiddleware())
			middlewares = append(middlewares, recoverMiddleware(currentName))
			
			// Always add logging middleware for request tracking
			middlewares = append(middlewares, loggerMiddleware(currentName))

			// Use OAuth authentication if configured, otherwise fall back to simple tokens
			hasOAuth := oauthServer != nil
			internal.LogTraceWithFields(currentName, "configuring authentication", map[string]interface{}{
				"oauth_enabled": hasOAuth,
			})

			if hasOAuth {
				internal.LogTraceWithFields(currentName, "adding OAuth middleware", nil)
				middlewares = append(middlewares, oauthServer.ValidateTokenMiddleware())
			} else if currentConfig.Options != nil && len(currentConfig.Options.AuthTokens) > 0 {
				internal.LogTraceWithFields(currentName, "adding token auth middleware", map[string]interface{}{
					"token_count": len(currentConfig.Options.AuthTokens),
				})
				middlewares = append(middlewares, newAuthMiddleware(currentConfig.Options.AuthTokens))
			} else {
				internal.LogTraceWithFields(currentName, "no authentication middleware configured", nil)
			}

			mcpRoute := path.Join(baseURL.Path, currentName)
			if !strings.HasPrefix(mcpRoute, "/") {
				mcpRoute = "/" + mcpRoute
			}
			if !strings.HasSuffix(mcpRoute, "/") {
				mcpRoute += "/"
			}

			internal.LogTraceWithFields(currentName, "registering route", map[string]interface{}{
				"route":            mcpRoute,
				"middleware_count": len(middlewares),
			})
			httpMux.Handle(mcpRoute, chainMiddleware(currentServer.SSEServer, middlewares...))

			httpServer.RegisterOnShutdown(func() {
				internal.Logf("<%s> Shutting down", currentName)
				_ = currentClient.Close()
			})

			internal.LogTraceWithFields(currentName, "MCP client initialization completed successfully", nil)
			return nil
		})
	}

	// Channel to signal errors that should trigger shutdown
	errChan := make(chan error, 2)

	// Wait for all MCP clients to initialize
	go func() {
		err := errorGroup.Wait()
		if err != nil {
			internal.Logf("Failed to initialize MCP clients: %v", err)
			errChan <- err
			return
		}
		internal.Logf("All clients initialized")
	}()

	// Start HTTP server
	go func() {
		internal.Logf("Starting SSE server")
		internal.Logf("SSE server listening on %s", cfg.Proxy.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			internal.Logf("HTTP server error: %v", err)
			errChan <- err
		}
	}()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		internal.Logf("Shutdown signal received: %v", sig)
	case err := <-errChan:
		internal.Logf("Shutting down due to error: %v", err)
	case <-ctx.Done():
		internal.Logf("Context cancelled, shutting down")
	}

	// Graceful shutdown
	internal.Logf("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		internal.Logf("Server shutdown error: %v", err)
		return err
	}

	internal.Logf("Server shutdown complete")
	return nil
}
