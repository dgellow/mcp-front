package integration

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicAuth(t *testing.T) {
	// Start mcp-front with basic auth config
	startMCPFront(t, "config/config.basic-auth-test.json",
		"ADMIN_PASSWORD=adminpass123",
		"USER_PASSWORD=userpass456",
	)

	// Wait for startup
	waitForMCPFront(t)

	t.Run("valid credentials", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/test-server/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:adminpass123")))
		req.Header.Set("Accept", "text/event-stream")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should get 503 since backend doesn't exist, but auth should pass
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("invalid password", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/test-server/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:wrongpass")))

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, `Basic realm="mcp-front"`, resp.Header.Get("WWW-Authenticate"))
	})

	t.Run("unknown user", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/test-server/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("unknown:adminpass123")))

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("missing auth header", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/test-server/sse", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, `Basic realm="mcp-front"`, resp.Header.Get("WWW-Authenticate"))
	})

	t.Run("access MCP endpoint with basic auth", func(t *testing.T) {
		// Test accessing a protected MCP endpoint
		req, err := http.NewRequest("GET", "http://localhost:8080/test-server/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:userpass456")))
		req.Header.Set("Accept", "text/event-stream")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should get 503 since backend doesn't exist, but auth should pass
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("bearer token with basic auth configured", func(t *testing.T) {
		// Server expects basic auth, bearer tokens should fail
		req, err := http.NewRequest("GET", "http://localhost:8080/test-server/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer sometoken")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
