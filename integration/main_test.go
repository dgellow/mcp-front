package integration

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestMain provides package-level setup and teardown for all integration tests
func TestMain(m *testing.M) {
	flag.Parse()

	// Build mcp-front binary once for all tests
	fmt.Println("Building mcp-front binary...")
	buildCmd := exec.Command("go", "build", "-o", "../cmd/mcp-front/mcp-front", "../cmd/mcp-front")
	if err := buildCmd.Run(); err != nil {
		fmt.Printf("Failed to build mcp-front: %v\n", err)
		os.Exit(1)
	}

	// Set up local log file for mcp-front output
	logFile := "mcp-front-test.log"
	os.Setenv("MCP_LOG_FILE", logFile)

	// Start test database once for all tests in this package
	fmt.Println("Starting test database...")
	dbCmd := exec.Command("docker", "compose", "up", "-d")
	if err := dbCmd.Run(); err != nil {
		fmt.Printf("Failed to start test database: %v\n", err)
		os.Exit(1)
	}

	// Track exit code for deferred cleanup
	var exitCode int

	// Set up cleanup on exit
	defer func() {
		fmt.Println("Cleaning up test database...")
		downCmd := exec.Command("docker", "compose", "down", "-v")
		if err := downCmd.Run(); err != nil {
			fmt.Printf("Warning: cleanup failed: %v\n", err)
		}

		// Show diagnostics if tests failed
		if exitCode != 0 {
			showTestFailureDiagnostics(logFile)
		}

		os.Exit(exitCode)
	}()

	// Wait for database to be ready
	fmt.Println("Waiting for database to be ready...")
	for i := 0; i < 30; i++ { // Wait up to 30 seconds
		checkCmd := exec.Command("docker", "compose", "exec", "-T", "test-postgres", "pg_isready", "-U", "testuser", "-d", "testdb")
		if err := checkCmd.Run(); err == nil {
			fmt.Println("Database is ready!")
			break
		}
		if i == 29 {
			fmt.Println("Database failed to become ready after 30 seconds")
			exitCode = 1
			return
		}
		time.Sleep(1 * time.Second)
	}

	// Run all tests in the package
	exitCode = m.Run()
}

// showTestFailureDiagnostics displays logs when tests fail
func showTestFailureDiagnostics(logFile string) {
	fmt.Println("\n========== TEST FAILURE DIAGNOSTICS ==========")

	// Show Docker compose logs
	fmt.Println("\nDocker logs:")
	fmt.Println("----------------------------------------------")
	logsCmd := exec.Command("docker", "compose", "logs", "--tail=50")
	logsCmd.Stdout = os.Stdout
	logsCmd.Stderr = os.Stderr
	logsCmd.Run()

	// Show mcp-front logs if available
	if _, err := os.Stat(logFile); err == nil {
		fmt.Println("\nmcp-front logs (last 50 lines):")
		fmt.Println("----------------------------------------------")
		tailCmd := exec.Command("tail", "-50", logFile)
		tailCmd.Stdout = os.Stdout
		tailCmd.Stderr = os.Stderr
		tailCmd.Run()
	}

	fmt.Println("\n==============================================")
}
