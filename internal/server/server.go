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

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
)

// Run starts and runs the MCP proxy server
func Run(cfg *config.Config) error {
	log.LogInfoWithFields("server", "Starting MCP proxy server", map[string]interface{}{
		"addr":       cfg.Proxy.Addr,
		"baseURL":    cfg.Proxy.BaseURL,
		"mcpServers": len(cfg.MCPServers),
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
		log.LogInfoWithFields("server", "HTTP server starting", map[string]interface{}{
			"addr": cfg.Proxy.Addr,
		})
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("server error: %w", err)
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var shutdownReason string
	select {
	case sig := <-sigChan:
		shutdownReason = fmt.Sprintf("signal %v", sig)
		log.LogInfoWithFields("server", "Received shutdown signal", map[string]interface{}{
			"signal": sig.String(),
		})
	case err := <-errChan:
		shutdownReason = fmt.Sprintf("error: %v", err)
		log.LogErrorWithFields("server", "Shutting down due to error", map[string]interface{}{
			"error": err.Error(),
		})
	case <-ctx.Done():
		shutdownReason = "context cancelled"
		log.LogInfoWithFields("server", "Context cancelled, shutting down", nil)
	}

	// Graceful shutdown
	log.LogInfoWithFields("server", "Starting graceful shutdown", map[string]interface{}{
		"reason":  shutdownReason,
		"timeout": "30s",
	})
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.LogErrorWithFields("server", "HTTP server shutdown error", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	// Shutdown the handler (which includes session manager)
	if err := handler.Shutdown(); err != nil {
		log.LogErrorWithFields("server", "Handler shutdown error", map[string]interface{}{
			"error": err.Error(),
		})
	}

	log.LogInfoWithFields("server", "Server shutdown complete", map[string]interface{}{
		"reason": shutdownReason,
	})
	return nil
}
