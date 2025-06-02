package integration

import (
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

// TestSimpleOAuth tests basic OAuth functionality without database
func TestSimpleOAuth(t *testing.T) {
	// Build mcp-front
	buildCmd := exec.Command("go", "build", "-o", "mcp-front", ".")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build mcp-front: %v", err)
	}

	// Start mcp-front with minimal OAuth config
	mcpCmd := exec.Command("../mcp-front", "-config", "config/config.test.json")
	mcpCmd.Env = []string{
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"MCP_FRONT_ENV=development",
	}
	
	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}
	defer func() {
		if mcpCmd.Process != nil {
			mcpCmd.Process.Kill()
			mcpCmd.Wait()
		}
	}()

	// Wait for startup
	if !waitForHealthCheck(t) {
		t.Fatal("mcp-front failed to start")
	}

	t.Log("✅ mcp-front started successfully with 32-byte JWT secret")
}

// TestJWTSecretLength tests different JWT secret lengths
func TestJWTSecretLength(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		shouldFail bool
	}{
		{"3-byte", "123", true},
		{"32-byte", "demo-jwt-secret-32-bytes-exactly!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build mcp-front
			buildCmd := exec.Command("go", "build", "-o", "mcp-front", ".")
			buildCmd.Dir = ".."
			if err := buildCmd.Run(); err != nil {
				t.Fatalf("Failed to build mcp-front: %v", err)
			}

			// Start mcp-front
			mcpCmd := exec.Command("../mcp-front", "-config", "config/config.test.json")
			mcpCmd.Env = []string{
				fmt.Sprintf("JWT_SECRET=%s", tt.secret),
				"MCP_FRONT_ENV=development",
			}
			
			if err := mcpCmd.Start(); err != nil {
				if tt.shouldFail {
					t.Logf("✅ Expected failure: %v", err)
					return
				}
				t.Fatalf("Failed to start mcp-front: %v", err)
			}
			defer func() {
				if mcpCmd.Process != nil {
					mcpCmd.Process.Kill()
					mcpCmd.Wait()
				}
			}()

			// Check if it stays running
			time.Sleep(2 * time.Second)
			
			healthy := waitForHealthCheckQuick(t)
			if tt.shouldFail && healthy {
				t.Fatal("Expected mcp-front to fail with short JWT secret")
			}
			if !tt.shouldFail && !healthy {
				t.Fatal("Expected mcp-front to succeed with proper JWT secret")
			}
			
			if tt.shouldFail {
				t.Logf("✅ Short JWT secret properly rejected")
			} else {
				t.Logf("✅ Proper JWT secret accepted")
			}
		})
	}
}

func waitForHealthCheck(t *testing.T) bool {
	for i := 0; i < 30; i++ {
		resp, err := http.Get("http://localhost:8080/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func waitForHealthCheckQuick(t *testing.T) bool {
	for i := 0; i < 5; i++ {
		resp, err := http.Get("http://localhost:8080/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	return false
}