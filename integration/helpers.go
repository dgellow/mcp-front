package integration

import (
	"flag"
	"os"
	"testing"
)

// TestMain provides test suite setup and teardown
func TestMain(m *testing.M) {
	flag.Parse()

	// Run tests
	code := m.Run()

	// Exit with test result code
	os.Exit(code)
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
