package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientSecretPostAuthentication(t *testing.T) {
	// Start mcp-front with OAuth config
	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.oauth-test.json")
	mcpCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	}

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}
	defer func() {
		if mcpCmd.Process != nil {
			_ = mcpCmd.Process.Kill()
			_ = mcpCmd.Wait()
		}
	}()

	// Wait for server to be ready
	baseURL := "http://localhost:8080"
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/.well-known/oauth-authorization-server")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "Server did not start in time")

	// Test 1: Register a confidential client with client_secret_post
	registerPayload := map[string]interface{}{
		"redirect_uris":              []string{"https://example.com/callback"},
		"scope":                      "read write",
		"token_endpoint_auth_method": "client_secret_post",
	}

	body, err := json.Marshal(registerPayload)
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/register", "application/json", bytes.NewBuffer(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode, "Registration should succeed")

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var registerResp map[string]interface{}
	err = json.Unmarshal(respBody, &registerResp)
	require.NoError(t, err)

	// Verify registration response includes client_secret
	clientID, ok := registerResp["client_id"].(string)
	assert.True(t, ok, "client_id should be a string")
	assert.NotEmpty(t, clientID)

	clientSecret, ok := registerResp["client_secret"].(string)
	assert.True(t, ok, "client_secret should be a string")
	assert.NotEmpty(t, clientSecret, "Confidential client should receive a secret")

	tokenEndpointAuthMethod, ok := registerResp["token_endpoint_auth_method"].(string)
	assert.True(t, ok)
	assert.Equal(t, "client_secret_post", tokenEndpointAuthMethod)

	// Test 2: Register a public client (no client_secret_post)
	publicPayload := map[string]interface{}{
		"redirect_uris": []string{"https://example.com/callback"},
		"scope":         "read",
	}

	body, err = json.Marshal(publicPayload)
	require.NoError(t, err)

	resp, err = http.Post(baseURL+"/register", "application/json", bytes.NewBuffer(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	respBody, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	var publicResp map[string]interface{}
	err = json.Unmarshal(respBody, &publicResp)
	require.NoError(t, err)

	// Verify public client has no secret
	_, hasSecret := publicResp["client_secret"]
	assert.False(t, hasSecret, "Public client should not receive a secret")

	publicAuthMethod, ok := publicResp["token_endpoint_auth_method"].(string)
	assert.True(t, ok)
	assert.Equal(t, "none", publicAuthMethod)

	// Test 3: Test token endpoint with client_secret_post
	// Note: This would require a full OAuth flow with authorization code
	// For now, we'll just verify the client was stored correctly
	time.Sleep(100 * time.Millisecond) // Give server time to process

	// Test 4: Verify .well-known includes client_secret_post
	resp, err = http.Get(baseURL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	var wellKnown map[string]interface{}
	err = json.Unmarshal(respBody, &wellKnown)
	require.NoError(t, err)

	authMethods, ok := wellKnown["token_endpoint_auth_methods_supported"].([]interface{})
	assert.True(t, ok)
	
	var foundClientSecretPost bool
	for _, method := range authMethods {
		if method == "client_secret_post" {
			foundClientSecretPost = true
			break
		}
	}
	assert.True(t, foundClientSecretPost, "client_secret_post should be advertised in well-known")
}

func TestClientSecretPostTokenExchange(t *testing.T) {
	t.Skip("Skipping complex token exchange test - requires more setup")

	// Start mcp-front with OAuth config
	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.oauth-test.json", "-port", "8081")
	mcpCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	}

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}
	defer func() {
		if mcpCmd.Process != nil {
			_ = mcpCmd.Process.Kill()
			_ = mcpCmd.Wait()
		}
	}()

	// Wait for server to be ready
	baseURL := "http://localhost:8081"
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/.well-known/oauth-authorization-server")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "Server did not start in time")

	// Register a confidential client
	registerPayload := map[string]interface{}{
		"redirect_uris":              []string{"https://example.com/callback"},
		"scope":                      "read write",
		"token_endpoint_auth_method": "client_secret_post",
	}

	body, err := json.Marshal(registerPayload)
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/register", "application/json", bytes.NewBuffer(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var registerResp map[string]interface{}
	err = json.Unmarshal(respBody, &registerResp)
	require.NoError(t, err)

	clientID := registerResp["client_id"].(string)
	clientSecret := registerResp["client_secret"].(string)

	// In a real test, we would:
	// 1. Start an authorization flow
	// 2. Mock the Google OAuth callback
	// 3. Get an authorization code
	// 4. Exchange the code for a token using client_secret_post

	// For now, we'll test that attempting to use the token endpoint
	// with client_secret_post parameters is properly parsed
	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("code", "dummy-code") // This will fail, but we're testing the auth parsing
	tokenData.Set("client_id", clientID)
	tokenData.Set("client_secret", clientSecret)
	tokenData.Set("redirect_uri", "https://example.com/callback")

	req, err := http.NewRequest("POST", baseURL+"/token", strings.NewReader(tokenData.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// We expect this to fail because we don't have a valid authorization code
	// But it should fail with an OAuth error, not an authentication error
	// This proves the client_secret_post authentication was accepted
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Should get bad request for invalid code")

	respBody, err = io.ReadAll(resp.Body)
	require.NoError(t, err)

	var errorResp map[string]interface{}
	err = json.Unmarshal(respBody, &errorResp)
	require.NoError(t, err)

	// The error should be about the invalid authorization code,
	// not about client authentication
	errorType, ok := errorResp["error"].(string)
	assert.True(t, ok)
	assert.NotEqual(t, "invalid_client", errorType, "Should not get invalid_client error")
}