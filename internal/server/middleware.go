package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal"
)

// MiddlewareFunc is a function that wraps an http.Handler
type MiddlewareFunc func(http.Handler) http.Handler

// chainMiddleware chains multiple middleware functions
func chainMiddleware(h http.Handler, middlewares ...MiddlewareFunc) http.Handler {
	for _, mw := range middlewares {
		h = mw(h)
	}
	return h
}

// corsMiddleware adds CORS headers to responses
func corsMiddleware(allowedOrigins []string) MiddlewareFunc {
	// Build a map for faster lookup
	allowedMap := make(map[string]bool)
	for _, origin := range allowedOrigins {
		allowedMap[origin] = true
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			
			// Only set CORS headers if origin is allowed
			if origin != "" && allowedMap[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			} else if len(allowedOrigins) == 0 {
				// If no allowed origins configured, allow all (development mode)
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
			// If origin not allowed, don't set Access-Control-Allow-Origin header
			
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control, mcp-protocol-version")
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

// responseWriter wraps http.ResponseWriter to capture status and bytes written
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

func (rw *responseWriter) Status() int {
	return rw.status
}

func (rw *responseWriter) BytesWritten() int {
	return rw.bytes
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.status = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

// loggerMiddleware adds request/response logging
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
			})
		})
	}
}

// recoverMiddleware recovers from panics
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

// newAuthMiddleware creates middleware for bearer token authentication
func newAuthMiddleware(tokens []string) MiddlewareFunc {
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(tokens) != 0 {
				authHeader := r.Header.Get("Authorization")

				if !strings.HasPrefix(authHeader, "Bearer ") {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				token := authHeader[7:] // Extract the actual token
				if _, ok := tokenSet[token]; !ok {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}