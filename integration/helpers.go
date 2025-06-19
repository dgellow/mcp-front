package integration

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestConfig holds all timeout configurations for integration tests
type TestConfig struct {
	SessionTimeout     string
	CleanupInterval    string
	CleanupWaitTime    string
	TimerResetWaitTime string
	MultiUserWaitTime  string
}

// GetTestConfig returns test configuration from environment variables or defaults
func GetTestConfig() TestConfig {
	c := TestConfig{
		SessionTimeout:     "10s",
		CleanupInterval:    "2s",
		CleanupWaitTime:    "15s",
		TimerResetWaitTime: "12s",
		MultiUserWaitTime:  "15s",
	}

	// Override from environment if set
	if v := os.Getenv("SESSION_TIMEOUT"); v != "" {
		c.SessionTimeout = v
	}
	if v := os.Getenv("SESSION_CLEANUP_INTERVAL"); v != "" {
		c.CleanupInterval = v
	}
	if v := os.Getenv("TEST_CLEANUP_WAIT_TIME"); v != "" {
		c.CleanupWaitTime = v
	}
	if v := os.Getenv("TEST_TIMER_RESET_WAIT_TIME"); v != "" {
		c.TimerResetWaitTime = v
	}
	if v := os.Getenv("TEST_MULTI_USER_WAIT_TIME"); v != "" {
		c.MultiUserWaitTime = v
	}

	return c
}

func waitForDB(t *testing.T) {
	waitForSec := 5
	for i := 0; i < waitForSec; i++ {
		// Check if container is running
		psCmd := exec.Command("docker", "compose", "ps", "-q", "test-postgres")
		if output, err := psCmd.Output(); err != nil || len(output) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		// Check if database is ready
		checkCmd := exec.Command("docker", "compose", "exec", "-T", "test-postgres", "pg_isready", "-U", "testuser", "-d", "testdb")
		if err := checkCmd.Run(); err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	t.Fatalf("Database failed to become ready after %d seconds", waitForSec)
}

// trace logs a message if TRACE environment variable is set
func trace(t *testing.T, format string, args ...interface{}) {
	if os.Getenv("TRACE") == "1" {
		t.Logf("TRACE: "+format, args...)
	}
}

// tracef logs a formatted message to stdout if TRACE is set (for use outside tests)
func tracef(format string, args ...interface{}) {
	if os.Getenv("TRACE") == "1" {
		fmt.Printf("TRACE: "+format+"\n", args...)
	}
}

// startMCPFront starts the mcp-front server with the given config and returns the command
func startMCPFront(t *testing.T, configPath string, extraEnv ...string) *exec.Cmd {
	mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", configPath)

	// Get test config for session timeouts
	testConfig := GetTestConfig()

	// Build default environment with test timeouts
	defaultEnv := []string{
		"SESSION_TIMEOUT=" + testConfig.SessionTimeout,
		"SESSION_CLEANUP_INTERVAL=" + testConfig.CleanupInterval,
	}

	// Start with system environment
	mcpCmd.Env = os.Environ()

	// Apply defaults first
	mcpCmd.Env = append(mcpCmd.Env, defaultEnv...)

	// Apply extra env (can override defaults)
	mcpCmd.Env = append(mcpCmd.Env, extraEnv...)

	// Pass through LOG_LEVEL and LOG_FORMAT if set
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		mcpCmd.Env = append(mcpCmd.Env, "LOG_LEVEL="+logLevel)
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		mcpCmd.Env = append(mcpCmd.Env, "LOG_FORMAT="+logFormat)
	}

	// Capture output to log file if MCP_LOG_FILE is set
	if logFile := os.Getenv("MCP_LOG_FILE"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			mcpCmd.Stderr = f
			mcpCmd.Stdout = f
			t.Cleanup(func() { f.Close() })
		}
	}

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	return mcpCmd
}

// stopMCPFront stops the mcp-front server
func stopMCPFront(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// waitForMCPFront waits for the mcp-front server to be ready
func waitForMCPFront(t *testing.T) {
	t.Helper()
	for i := 0; i < 10; i++ {
		resp, err := http.Get("http://localhost:8080/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("mcp-front failed to become ready after 10 seconds")
}

// getMCPContainers returns a list of running mcp/postgres container IDs
func getMCPContainers() []string {
	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}", "--filter", "ancestor=mcp/postgres")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var containers []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line != "" {
			containers = append(containers, line)
		}
	}
	return containers
}

// cleanupContainers forces cleanup of containers that weren't in the initial set
func cleanupContainers(t *testing.T, initialContainers []string) {
	time.Sleep(2 * time.Second)
	containers := getMCPContainers()
	for _, container := range containers {
		isInitial := false
		for _, initial := range initialContainers {
			if container == initial {
				isInitial = true
				break
			}
		}
		if !isInitial {
			t.Logf("Force stopping container: %s...", container)
			if err := exec.Command("docker", "stop", container).Run(); err != nil {
				t.Logf("Failed to stop container %s: %v", container, err)
			} else {
				t.Logf("Stopped container: %s", container)
			}
		}
	}
}

// TestQuickSmoke provides a fast validation test
func TestQuickSmoke(t *testing.T) {
	t.Log("Running quick smoke test...")

	// Just verify the test infrastructure works
	client := NewMCPClient("http://localhost:8080")
	if client == nil {
		t.Fatal("Failed to create client")
	}

	if err := client.Authenticate(); err != nil {
		t.Fatal("Failed to set up authentication")
	}

	t.Log("Quick smoke test passed - test infrastructure is working")
}
