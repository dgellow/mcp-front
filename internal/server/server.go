package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/config"
)

// Run starts and runs the MCP proxy server
func Run(cfg *config.Config) error {
	internal.LogInfoWithFields("server", "Starting MCP proxy server", map[string]interface{}{
		"addr":    cfg.Proxy.Addr,
		"baseURL": cfg.Proxy.BaseURL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the server handler
	handler, err := NewServer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	httpServer := &http.Server{
		Addr:    cfg.Proxy.Addr,
		Handler: handler,
	}

	// Channel to signal errors that should trigger shutdown
	errChan := make(chan error, 1)

	// Start HTTP server
	go func() {
		internal.Logf("Starting SSE server")
		internal.Logf("Server listening on %s", cfg.Proxy.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("server error: %w", err)
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		internal.Logf("Received signal: %v", sig)
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

	// Shutdown the handler (which includes session manager)
	if err := handler.Shutdown(); err != nil {
		internal.Logf("Handler shutdown error: %v", err)
	}

	internal.Logf("Server shutdown complete")
	return nil
}
