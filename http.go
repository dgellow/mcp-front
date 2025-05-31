package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

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

	baseURL, err := url.Parse(config.McpProxy.BaseURL)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var errorGroup errgroup.Group
	httpMux := http.NewServeMux()
	httpServer := &http.Server{
		Addr:    config.McpProxy.Addr,
		Handler: httpMux,
	}
	info := mcp.Implementation{
		Name:    config.McpProxy.Name,
		Version: BuildVersion,
	}

	// Initialize OAuth server if OAuth config is provided
	var oauthServer *OAuthServer
	if config.OAuth != nil {
		oauthServer, err = NewOAuthServer(config.OAuth)
		if err != nil {
			return err
		}

		// Register OAuth endpoints
		httpMux.HandleFunc("/.well-known/oauth-authorization-server", oauthServer.WellKnownHandler)
		httpMux.HandleFunc("/authorize", oauthServer.AuthorizeHandler)
		httpMux.HandleFunc("/oauth/callback", oauthServer.GoogleCallbackHandler)
		httpMux.HandleFunc("/token", oauthServer.TokenHandler)
		httpMux.HandleFunc("/register", oauthServer.RegisterHandler)

		logf("OAuth 2.1 server initialized with issuer: %s", config.OAuth.Issuer)
	}

	for name, clientConfig := range config.McpServers {
		mcpClient, err := newMCPClient(name, clientConfig)
		if err != nil {
			logf("<%s> Failed to create client: %v", name, err)
			os.Exit(1)
		}
		server := newMCPServer(name, BuildVersion, config.McpProxy.BaseURL, clientConfig)
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
			middlewares = append(middlewares, recoverMiddleware(name))
			if boolOrDefault(clientConfig.Options.LogEnabled, false) {
				middlewares = append(middlewares, loggerMiddleware(name))
			}

			// Use OAuth authentication if configured, otherwise fall back to simple tokens
			if oauthServer != nil {
				middlewares = append(middlewares, oauthServer.ValidateTokenMiddleware())
			} else if len(clientConfig.Options.AuthTokens) > 0 {
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
		logf("SSE server listening on %s", config.McpProxy.Addr)
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
