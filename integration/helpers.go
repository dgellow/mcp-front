package integration

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func startTestDB(t *testing.T) func() {
	dbCmd := exec.Command("docker", "compose", "up", "-d")
	err := dbCmd.Run()
	require.NoError(t, err, "Failed to start test database")
	return func() {
		downCmd := exec.Command("docker", "compose", "down", "-v")
		err := downCmd.Run()
		require.NoError(t, err, "Failed to stop test database")
	}
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

// TestMain provides test suite setup and teardown
func TestMain(m *testing.M) {
	flag.Parse()

	// Run tests
	code := m.Run()

	// Exit with test result code
	os.Exit(code)
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

	t.Log("✅ Quick smoke test passed - test infrastructure is working")
}
