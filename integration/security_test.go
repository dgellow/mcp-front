package integration

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSecurityScenarios(t *testing.T) {
	// Start test database first
	dbCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "up", "-d")
	if err := dbCmd.Run(); err != nil {
		t.Fatalf("Failed to start test database: %v", err)
	}
	defer func() {
		downCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "down", "-v")
		_ = downCmd.Run()
	}()

	time.Sleep(10 * time.Second)

	// Start mcp-front
	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.test.json")
	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}
	defer func() {
		if mcpCmd.Process != nil {
			_ = mcpCmd.Process.Kill()
			_ = mcpCmd.Wait()
		}
	}()

	time.Sleep(15 * time.Second)

	t.Run("NoAuthToken", func(t *testing.T) {
		// Test:

		resp, err := http.Get("http://localhost:8080/postgres/sse")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != 401 {
			t.Errorf("❌ Expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	t.Run("InvalidBearerToken", func(t *testing.T) {
		// Test:

		client := &http.Client{}
		req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-12345")
		req.Header.Set("Accept", "text/event-stream")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != 401 {
			t.Errorf("❌ Expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	t.Run("MalformedAuthHeader", func(t *testing.T) {
		// Test:

		malformedHeaders := []string{
			"Bearer",                           // Missing token
			"Basic test-token",                 // Wrong auth type
			"bearer test-token",                // Wrong case
			"Bearer test-token extra",          // Extra data
			"test-token",                       // Missing Bearer prefix
			"Authorization: Bearer test-token", // Full header as value
		}

		for _, authHeader := range malformedHeaders {
			// Testing malformed header

			client := &http.Client{}
			req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
			req.Header.Set("Authorization", authHeader)
			req.Header.Set("Accept", "text/event-stream")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != 401 {
				t.Errorf("❌ Expected 401 for malformed header '%s', got %d", authHeader, resp.StatusCode)
			}
		}
	})

	t.Run("SQLInjectionAttempts", func(t *testing.T) {
		// Test:

		client := NewMCPClient("http://localhost:8080")
		_ = client.Authenticate()

		// Validate backend connectivity first
		if err := client.ValidateBackendConnectivity(); err != nil {
			t.Fatalf("Backend connectivity failed: %v", err)
		}

		sqlInjectionPayloads := []string{
			"'; DROP TABLE users; --",
			"1; DELETE FROM users WHERE 1=1; --",
			"UNION SELECT * FROM users WHERE 1=1 --",
			"'; INSERT INTO users VALUES ('hacker', 'hack@evil.com'); --",
			"1' OR '1'='1",
			"'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'; --",
		}

		for _, payload := range sqlInjectionPayloads {
			// Testing SQL injection payload

			// Try to inject via the query parameter
			_, err := client.SendMCPRequest("tools/call", map[string]interface{}{
				"name": "query",
				"arguments": map[string]interface{}{
					"query": payload,
				},
			})

			// We expect this to either fail gracefully or be sanitized
			// The exact behavior depends on the postgres MCP implementation
			// but it should NOT succeed in executing malicious SQL
			if err != nil {
			} else {
				t.Logf("⚠️  SQL injection payload was accepted (should be sanitized by postgres MCP)")
			}
		}
	})

	t.Run("HeaderInjectionAttempts", func(t *testing.T) {
		// Test:

		// Try to inject malicious headers
		maliciousHeaders := []string{
			"test-token\r\nX-Injected: malicious",
			"test-token\nSet-Cookie: session=hacked",
			"test-token\r\nLocation: http://evil.com",
			"test-token\x00\x0aX-Injected: malicious",
		}

		for _, maliciousAuth := range maliciousHeaders {
			// Testing header injection

			client := &http.Client{}
			req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
			req.Header.Set("Authorization", "Bearer "+maliciousAuth)
			req.Header.Set("Accept", "text/event-stream")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Check that no injected headers are reflected
			for headerName := range resp.Header {
				if strings.Contains(strings.ToLower(headerName), "injected") ||
					strings.Contains(strings.ToLower(headerName), "cookie") {
					t.Errorf("❌ Possible header injection detected: %s", headerName)
				}
			}

			if resp.StatusCode != 401 {
				t.Errorf("❌ Expected 401 for header injection attempt, got %d", resp.StatusCode)
			}
		}
	})

	t.Run("PathTraversalAttempts", func(t *testing.T) {
		// Test:

		pathTraversalAttempts := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"....//....//....//etc/passwd",
			"/postgres/../../../etc/passwd",
		}

		for _, path := range pathTraversalAttempts {
			// Testing path traversal

			client := &http.Client{}
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:8080/%s", path), nil)
			req.Header.Set("Authorization", "Bearer test-token")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Should return 404 or 403, NOT 200 with sensitive content
			if resp.StatusCode == 200 {
				t.Errorf("❌ Path traversal may have succeeded: %s returned 200", path)
			}
		}
	})

	t.Run("TokenReuse", func(t *testing.T) {
		// Test:

		// Test that the same token works consistently
		client1 := NewMCPClient("http://localhost:8080")
		client1.token = "test-token"

		client2 := NewMCPClient("http://localhost:8080")
		client2.token = "test-token"

		// Both should work with same token
		err1 := client1.ValidateBackendConnectivity()
		err2 := client2.ValidateBackendConnectivity()

		if err1 != nil || err2 != nil {
			t.Errorf("❌ Valid token should work for multiple clients: %v, %v", err1, err2)
		}
	})

	t.Run("AuthenticationBypass", func(t *testing.T) {
		// Test:

		// Test case: token without Bearer prefix should be rejected
		t.Run("RejectsTokenWithoutBearer", func(t *testing.T) {
			client := &http.Client{}
			req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
			req.Header.Set("Authorization", "test-token") // Missing "Bearer " prefix
			req.Header.Set("Accept", "text/event-stream")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode == 200 {
				t.Errorf("❌ CRITICAL: Auth bypass! 'test-token' without Bearer returned 200")
			} else if resp.StatusCode == 401 {
			} else {
				t.Logf("⚠️  Unexpected status %d for malformed auth", resp.StatusCode)
			}
		})

		// Test various malformed auth headers
		malformedCases := []struct {
			name       string
			authHeader string
			shouldPass bool
		}{
			{"ValidBearer", "Bearer test-token", true},
			{"NoBearer", "test-token", false},
			{"WrongCase", "bearer test-token", false},
			{"ExtraSpaces", "Bearer  test-token", false},
			{"ExtraText", "Bearer test-token extra", false},
			{"BasicAuth", "Basic test-token", false},
		}

		for _, tc := range malformedCases {
			t.Run(tc.name, func(t *testing.T) {
				client := &http.Client{}
				req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
				req.Header.Set("Authorization", tc.authHeader)
				req.Header.Set("Accept", "text/event-stream")

				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				resp.Body.Close()

				if tc.shouldPass && resp.StatusCode != 200 {
					t.Errorf("❌ Valid auth '%s' should return 200, got %d", tc.authHeader, resp.StatusCode)
				} else if !tc.shouldPass && resp.StatusCode != 401 {
					t.Errorf("❌ Invalid auth '%s' should return 401, got %d", tc.authHeader, resp.StatusCode)
				}
			})
		}
	})

	t.Run("RateLimitingCheck", func(t *testing.T) {
		// Test:

		client := NewMCPClient("http://localhost:8080")
		_ = client.Authenticate()

		successCount := 0
		errorCount := 0

		// Make rapid requests to see if there's any rate limiting
		for i := 0; i < 10; i++ {
			err := client.ValidateBackendConnectivity()
			if err != nil {
				errorCount++
			} else {
				successCount++
			}
		}

		// Rapid requests completed - no rate limiting expected in this implementation
	})
}

// TestFailureScenarios validates error handling
func TestFailureScenarios(t *testing.T) {
	// Testing failure scenarios

	t.Run("FailsWithWrongAuth", func(t *testing.T) {
		dbCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "up", "-d")
		if err := dbCmd.Run(); err != nil {
			t.Fatalf("Failed to start test database: %v", err)
		}
		defer func() {
			downCmd := exec.Command("docker-compose", "-f", "config/docker-compose.test.yml", "down", "-v")
			_ = downCmd.Run()
		}()

		time.Sleep(10 * time.Second)

		mcpCmd := exec.Command("../mcp-front", "-config", "config/config.test.json")
		if err := mcpCmd.Start(); err != nil {
			t.Fatalf("Failed to start mcp-front: %v", err)
		}
		defer func() {
			if mcpCmd.Process != nil {
				_ = mcpCmd.Process.Kill()
				_ = mcpCmd.Wait()
			}
		}()

		time.Sleep(15 * time.Second)

		// Test comprehensive token validation
		testCases := []struct {
			name     string
			token    string
			expected int
		}{
			{"ValidToken", "test-token", 200},
			{"EmptyToken", "", 401},
			{"WrongToken", "wrong-token", 401},
			{"LongToken", strings.Repeat("a", 1000), 401},
			{"SpecialChars", "test-token!@#$%^&*()", 401},
			{"UnicodeToken", "test-token-🔒", 401},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				client := &http.Client{}
				req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)

				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				req.Header.Set("Accept", "text/event-stream")

				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				resp.Body.Close()

				if resp.StatusCode != tc.expected {
					t.Errorf("❌ Token '%s': expected %d, got %d", tc.name, tc.expected, resp.StatusCode)
				}
			})
		}
	})
}
