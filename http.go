package main

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

	"github.com/dgellow/mcp-front/oauth"
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
			logf("<%s> Request [%s] %s", prefix, r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

func recoverMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logf("<%s> Recovered from panic: %v", prefix, err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func startHTTPServer(config *Config) error {

	baseURL, err := url.Parse(fmt.Sprintf("%v", config.Proxy.BaseURL))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var errorGroup errgroup.Group
	httpMux := http.NewServeMux()
	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%v", config.Proxy.Addr),
		Handler: httpMux,
	}
	info := mcp.Implementation{
		Name:    config.Proxy.Name,
		Version: BuildVersion,
	}

	// Initialize OAuth server if OAuth config is provided
	var oauthServer *oauth.Server
	if oauthAuth, ok := config.Proxy.Auth.(*OAuthAuthConfig); ok && oauthAuth != nil {
		logger.Debug("initializing OAuth 2.1 server")
		
		// Validate required OAuth fields
		if oauthAuth.Issuer == nil || oauthAuth.TokenTTL == "" {
			logger.Error("OAuth configuration missing required fields: issuer and token_ttl are required")
			return fmt.Errorf("OAuth configuration missing required fields: issuer and token_ttl are required")
		}
		
		logger.Debug("parsing OAuth token TTL", "ttl", oauthAuth.TokenTTL)
		ttl, err := time.ParseDuration(oauthAuth.TokenTTL)
		if err != nil {
			logger.Error("failed to parse OAuth token TTL", "ttl", oauthAuth.TokenTTL, "error", err)
			return fmt.Errorf("parsing OAuth token TTL: %w", err)
		}

		oauthConfig := oauth.Config{
			Issuer:             fmt.Sprintf("%v", oauthAuth.Issuer),
			TokenTTL:           ttl,
			AllowedDomains:     oauthAuth.AllowedDomains,
			GoogleClientID:     fmt.Sprintf("%v", oauthAuth.GoogleClientID),
			GoogleClientSecret: fmt.Sprintf("%v", oauthAuth.GoogleClientSecret),
			GoogleRedirectURI:  fmt.Sprintf("%v", oauthAuth.GoogleRedirectURI),
			JWTSecret:          fmt.Sprintf("%v", oauthAuth.JWTSecret),
		}
		
		logTraceWithFields("oauth", "creating OAuth server", map[string]interface{}{
			"issuer":          oauthConfig.Issuer,
			"token_ttl":       oauthConfig.TokenTTL.String(),
			"allowed_domains": oauthConfig.AllowedDomains,
		})
		
		oauthServer, err = oauth.NewServer(oauthConfig)
		if err != nil {
			logErrorWithFields("oauth", "failed to create OAuth server", map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to create OAuth server: %w", err)
		}
		
		if oauthServer == nil {
			logErrorWithFields("oauth", "OAuth server creation returned nil", nil)
			return fmt.Errorf("OAuth server creation returned nil")
		}

		logTraceWithFields("oauth", "registering OAuth endpoints", map[string]interface{}{
			"endpoints": []string{
				"/.well-known/oauth-authorization-server",
				"/authorize",
				"/oauth/callback", 
				"/token",
				"/register",
				"/debug/clients",
			},
		})
		
		// Register OAuth endpoints with CORS middleware
		corsHandler := corsMiddleware()
		httpMux.Handle("/.well-known/oauth-authorization-server", corsHandler(http.HandlerFunc(oauthServer.WellKnownHandler)))
		httpMux.Handle("/authorize", corsHandler(http.HandlerFunc(oauthServer.AuthorizeHandler)))
		httpMux.Handle("/oauth/callback", corsHandler(http.HandlerFunc(oauthServer.GoogleCallbackHandler)))
		httpMux.Handle("/token", corsHandler(http.HandlerFunc(oauthServer.TokenHandler)))
		httpMux.Handle("/register", corsHandler(http.HandlerFunc(oauthServer.RegisterHandler)))
		
		// Debug endpoint to see registered clients
		httpMux.Handle("/debug/clients", corsHandler(http.HandlerFunc(oauthServer.DebugClientsHandler)))

		logInfoWithFields("oauth", "OAuth 2.1 server initialized", map[string]interface{}{
			"issuer": oauthAuth.Issuer,
		})
	} else {
		logger.Debug("no OAuth configuration found, using token-based authentication")
	}

	// Add health check endpoint
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"mcp-front"}`))
	})

	for name, clientConfig := range config.MCPServers {
		mcpClient, err := newMCPClient(name, clientConfig)
		if err != nil {
			logf("<%s> Failed to create client: %v", name, err)
			os.Exit(1)
		}
		server := newMCPServer(name, BuildVersion, fmt.Sprintf("%v", config.Proxy.BaseURL), clientConfig)
		
		// Capture loop variables to avoid closure issues
		currentName := name
		currentClient := mcpClient
		currentServer := server
		currentConfig := clientConfig
		
		errorGroup.Go(func() error {
			logTraceWithFields(currentName, "starting MCP client initialization", nil)
			
			// Add nil checks to prevent panics
			if currentClient == nil {
				logErrorWithFields(currentName, "client is nil", nil)
				return fmt.Errorf("<%s> client is nil", currentName)
			}
			if currentServer == nil || currentServer.mcpServer == nil {
				logErrorWithFields(currentName, "server or mcpServer is nil", nil)
				return fmt.Errorf("<%s> server or mcpServer is nil", currentName)
			}
			
			logTraceWithFields(currentName, "client and server objects validated", nil)
			logInfoWithFields(currentName, "connecting to MCP server", nil)
			addErr := currentClient.addToMCPServer(ctx, info, currentServer.mcpServer)
			if addErr != nil {
				logErrorWithFields(currentName, "failed to add client to server", map[string]interface{}{
					"error": addErr.Error(),
				})
				if currentConfig != nil && currentConfig.Options != nil && boolOrDefault(currentConfig.Options.PanicIfInvalid, false) {
					return addErr
				}
				return nil
			}
			logInfoWithFields(currentName, "connected to MCP server", nil)

			logTraceWithFields(currentName, "setting up middleware chain", nil)
			middlewares := make([]MiddlewareFunc, 0)
			
			// Add CORS as the FIRST middleware to handle OPTIONS before auth
			middlewares = append(middlewares, corsMiddleware())
			middlewares = append(middlewares, recoverMiddleware(currentName))
			
			// Add logging middleware if enabled and Options is not nil
			hasOptions := currentConfig.Options != nil
			logTraceWithFields(currentName, "checking logging configuration", map[string]interface{}{
				"has_options": hasOptions,
			})
			
			if hasOptions && boolOrDefault(currentConfig.Options.LogEnabled, false) {
				logTraceWithFields(currentName, "adding logger middleware", nil)
				middlewares = append(middlewares, loggerMiddleware(currentName))
			} else {
				logEnabled := hasOptions && currentConfig.Options.LogEnabled != nil && *currentConfig.Options.LogEnabled
				logTraceWithFields(currentName, "skipping logger middleware", map[string]interface{}{
					"has_options":   hasOptions,
					"log_enabled":   logEnabled,
				})
			}

			// Use OAuth authentication if configured, otherwise fall back to simple tokens
			hasOAuth := oauthServer != nil
			logTraceWithFields(currentName, "configuring authentication", map[string]interface{}{
				"oauth_enabled": hasOAuth,
			})
			
			if hasOAuth {
				logTraceWithFields(currentName, "adding OAuth middleware", nil)
				middlewares = append(middlewares, oauthServer.ValidateTokenMiddleware())
			} else if hasOptions && len(currentConfig.Options.AuthTokens) > 0 {
				logTraceWithFields(currentName, "adding token auth middleware", map[string]interface{}{
					"token_count": len(currentConfig.Options.AuthTokens),
				})
				middlewares = append(middlewares, newAuthMiddleware(currentConfig.Options.AuthTokens))
			} else {
				logTraceWithFields(currentName, "no authentication middleware configured", nil)
			}
			
			mcpRoute := path.Join(baseURL.Path, currentName)
			if !strings.HasPrefix(mcpRoute, "/") {
				mcpRoute = "/" + mcpRoute
			}
			if !strings.HasSuffix(mcpRoute, "/") {
				mcpRoute += "/"
			}
			
			logTrace("<%s> Registering route %s with %d middlewares", currentName, mcpRoute, len(middlewares))
			httpMux.Handle(mcpRoute, chainMiddleware(currentServer.sseServer, middlewares...))
			
			httpServer.RegisterOnShutdown(func() {
				logf("<%s> Shutting down", currentName)
				_ = currentClient.Close()
			})
			
			logTrace("<%s> MCP client initialization completed successfully", currentName)
			return nil
		})
	}

	// Channel to signal errors that should trigger shutdown
	errChan := make(chan error, 2)
	
	// Wait for all MCP clients to initialize
	go func() {
		err := errorGroup.Wait()
		if err != nil {
			logf("Failed to initialize MCP clients: %v", err)
			errChan <- err
			return
		}
		logf("All clients initialized")
	}()

	// Start HTTP server
	go func() {
		logf("Starting SSE server")
		logf("SSE server listening on %s", config.Proxy.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("HTTP server error: %v", err)
			errChan <- err
		}
	}()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logf("Shutdown signal received: %v", sig)
	case err := <-errChan:
		logf("Shutting down due to error: %v", err)
	case <-ctx.Done():
		logf("Context cancelled, shutting down")
	}

	// Graceful shutdown
	logf("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logf("Server shutdown error: %v", err)
		return err
	}
	
	logf("Server shutdown complete")
	return nil
}
