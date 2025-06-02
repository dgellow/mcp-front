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
	if oauthAuth, ok := config.Proxy.Auth.(*OAuthAuthConfig); ok {
		ttl, err := time.ParseDuration(oauthAuth.TokenTTL)
		if err != nil {
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
		oauthServer, err = oauth.NewServer(oauthConfig)
		if err != nil {
			return err
		}

		// Register OAuth endpoints with CORS middleware
		corsHandler := corsMiddleware()
		httpMux.Handle("/.well-known/oauth-authorization-server", corsHandler(http.HandlerFunc(oauthServer.WellKnownHandler)))
		httpMux.Handle("/authorize", corsHandler(http.HandlerFunc(oauthServer.AuthorizeHandler)))
		httpMux.Handle("/oauth/callback", corsHandler(http.HandlerFunc(oauthServer.GoogleCallbackHandler)))
		httpMux.Handle("/token", corsHandler(http.HandlerFunc(oauthServer.TokenHandler)))
		httpMux.Handle("/register", corsHandler(http.HandlerFunc(oauthServer.RegisterHandler)))
		
		// Debug endpoint to see registered clients
		httpMux.Handle("/debug/clients", corsHandler(http.HandlerFunc(oauthServer.DebugClientsHandler)))

		logf("OAuth 2.1 server initialized with issuer: %s", oauthAuth.Issuer)
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
		errorGroup.Go(func() error {
			logf("<%s> Connecting", name)
			addErr := mcpClient.addToMCPServer(ctx, info, server.mcpServer)
			if addErr != nil {
				logf("<%s> Failed to add client to server: %v", name, addErr)
				if boolOrDefault(clientConfig.Options.PanicIfInvalid, false) {
					return addErr
				}
				return nil
			}
			logf("<%s> Connected", name)

			middlewares := make([]MiddlewareFunc, 0)
			
			// Add CORS as the FIRST middleware to handle OPTIONS before auth
			middlewares = append(middlewares, corsMiddleware())
			middlewares = append(middlewares, recoverMiddleware(name))
			if boolOrDefault(clientConfig.Options.LogEnabled, false) {
				middlewares = append(middlewares, loggerMiddleware(name))
			}

			// Use OAuth authentication if configured, otherwise fall back to simple tokens
			if oauthServer != nil {
				middlewares = append(middlewares, oauthServer.ValidateTokenMiddleware())
			} else if clientConfig.Options != nil && len(clientConfig.Options.AuthTokens) > 0 {
				middlewares = append(middlewares, newAuthMiddleware(clientConfig.Options.AuthTokens))
			}
			mcpRoute := path.Join(baseURL.Path, name)
			if !strings.HasPrefix(mcpRoute, "/") {
				mcpRoute = "/" + mcpRoute
			}
			if !strings.HasSuffix(mcpRoute, "/") {
				mcpRoute += "/"
			}
			httpMux.Handle(mcpRoute, chainMiddleware(server.sseServer, middlewares...))
			httpServer.RegisterOnShutdown(func() {
				logf("<%s> Shutting down", name)
				_ = mcpClient.Close()
			})
			return nil
		})
	}

	go func() {
		err := errorGroup.Wait()
		if err != nil {
			logf("Failed to add clients: %v", err)
			os.Exit(1)
		}
		logf("All clients initialized")
	}()

	go func() {
		logf("Starting SSE server")
		logf("SSE server listening on %s", config.Proxy.Addr)
		hErr := httpServer.ListenAndServe()
		if hErr != nil && !errors.Is(hErr, http.ErrServerClosed) {
			logf("Failed to start server: %v", hErr)
			os.Exit(1)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	logf("Shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()

	err = httpServer.Shutdown(shutdownCtx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
