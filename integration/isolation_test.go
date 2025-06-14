package integration

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestMultiUserSessionIsolation validates that multiple users have separate stdio instances
func TestMultiUserSessionIsolation(t *testing.T) {
	trace(t, "Starting multi-user session isolation test")

	// Start test database
	closeDB := startTestDB(t)
	defer closeDB()
	waitForDB(t)

	// Start mcp-front with bearer token auth
	trace(t, "Starting mcp-front")
	mcpCmd := startMCPFront(t, "config/config.test.json")
	defer stopMCPFront(mcpCmd)
	waitForMCPFront(t)

	// Helper function to get mcp/postgres containers
	getMCPContainers := func() []string {
		cmd := exec.Command("docker", "ps", "--format", "{{.ID}}", "--filter", "ancestor=mcp/postgres")
		output, err := cmd.Output()
		if err != nil {
			t.Logf("Failed to list Docker containers: %v", err)
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

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create two clients with different auth tokens
	client1 := NewMCPClient("http://localhost:8080")
	client1.SetAuthToken("test-token") // First user
	defer client1.Close()

	client2 := NewMCPClient("http://localhost:8080")
	client2.SetAuthToken("alt-test-token") // Second user
	defer client2.Close()

	// Step 1: First user connects and sends a query
	t.Log("Step 1: First user connects and sends a query")
	if err := client1.Connect(); err != nil {
		t.Fatalf("Client1 failed to connect: %v", err)
	}
	t.Logf("Client1 connected with session: %s", client1.sessionID)

	// Check containers after first user connects
	containersAfterClient1 := getMCPContainers()
	t.Logf("Containers after client1 connects: %d", len(containersAfterClient1))
	
	// Find new container for client1
	var client1Container string
	for _, container := range containersAfterClient1 {
		isNew := true
		for _, initial := range initialContainers {
			if container == initial {
				isNew = false
				break
			}
		}
		if isNew {
			client1Container = container
			t.Logf("Client1 got new container: %s", container)
			break
		}
	}
	
	if client1Container == "" {
		t.Error("No new container created for client1")
	}

	query1Result, err := client1.SendMCPRequest("tools/call", map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"sql": "SELECT 'user1-query1' as test_id, COUNT(*) as count FROM users",
		},
	})
	if err != nil {
		t.Fatalf("Client1 query 1 failed: %v", err)
	}
	t.Logf("Client1 query 1 result: %+v", query1Result)

	// Step 2: Second user connects and sends a query
	t.Log("\nStep 2: Second user connects and sends a query")
	if err := client2.Connect(); err != nil {
		t.Fatalf("Client2 failed to connect: %v", err)
	}
	t.Logf("Client2 connected with session: %s", client2.sessionID)

	// Verify different sessions
	if client1.sessionID == client2.sessionID {
		t.Errorf("Expected different sessions for different users, but both got: %s", client1.sessionID)
	}

	// Check containers after second user connects
	containersAfterClient2 := getMCPContainers()
	t.Logf("Containers after client2 connects: %d", len(containersAfterClient2))
	
	// Find new container for client2
	var client2Container string
	for _, container := range containersAfterClient2 {
		isNew := true
		for _, existing := range containersAfterClient1 {
			if container == existing {
				isNew = false
				break
			}
		}
		if isNew {
			client2Container = container
			t.Logf("Client2 got new container: %s", container)
			break
		}
	}
	
	if client2Container == "" {
		t.Error("No new container created for client2")
	}
	
	// Verify that client1 and client2 have different containers
	if client1Container != "" && client2Container != "" && client1Container == client2Container {
		t.Errorf("CRITICAL: Both users are using the same Docker container! Container ID: %s", client1Container)
		t.Error("This indicates session isolation is NOT working - users are sharing the same mcp/postgres instance")
	} else if client1Container != "" && client2Container != "" {
		t.Logf("✓ Confirmed different stdio processes: User1 container=%s, User2 container=%s", client1Container, client2Container)
	}

	query2Result, err := client2.SendMCPRequest("tools/call", map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"sql": "SELECT 'user2-query1' as test_id, COUNT(*) as count FROM orders",
		},
	})
	if err != nil {
		t.Fatalf("Client2 query 1 failed: %v", err)
	}
	t.Logf("Client2 query 1 result: %+v", query2Result)

	// Step 3: First user sends another query
	t.Log("\nStep 3: First user sends another query")
	query3Result, err := client1.SendMCPRequest("tools/call", map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"sql": "SELECT 'user1-query2' as test_id, current_timestamp as ts",
		},
	})
	if err != nil {
		t.Fatalf("Client1 query 2 failed: %v", err)
	}
	t.Logf("Client1 query 2 result: %+v", query3Result)

	// Step 4: First user sends another query
	t.Log("\nStep 4: First user sends another query")
	query4Result, err := client1.SendMCPRequest("tools/call", map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"sql": "SELECT 'user1-query3' as test_id, version() as db_version",
		},
	})
	if err != nil {
		t.Fatalf("Client1 query 3 failed: %v", err)
	}
	t.Logf("Client1 query 3 result: %+v", query4Result)

	// Step 5: Second user sends a query
	t.Log("\nStep 5: Second user sends a query")
	query5Result, err := client2.SendMCPRequest("tools/call", map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"sql": "SELECT 'user2-query2' as test_id, current_database() as db_name",
		},
	})
	if err != nil {
		t.Fatalf("Client2 query 2 failed: %v", err)
	}
	t.Logf("Client2 query 2 result: %+v", query5Result)

	// Final verification
	finalContainers := getMCPContainers()
	t.Log("\n=== Container Summary ===")
	t.Logf("Initial containers: %d", len(initialContainers))
	t.Logf("Final containers: %d", len(finalContainers))
	t.Logf("New containers created: %d", len(finalContainers)-len(initialContainers))
	
	// We should have exactly 2 new containers (one for each user)
	expectedNewContainers := 2
	actualNewContainers := len(finalContainers) - len(initialContainers)
	if actualNewContainers != expectedNewContainers {
		t.Errorf("Expected %d new containers, but got %d", expectedNewContainers, actualNewContainers)
	}

	// Verify session isolation
	t.Log("\n=== Session Isolation Summary ===")
	t.Logf("Client1 session: %s", client1.sessionID)
	t.Logf("Client2 session: %s", client2.sessionID)
	if client1Container != "" {
		t.Logf("Client1 container: %s", client1Container)
	}
	if client2Container != "" {
		t.Logf("Client2 container: %s", client2Container)
	}
	
	// Final test result
	if client1.sessionID != client2.sessionID && client1Container != "" && client2Container != "" && client1Container != client2Container {
		t.Log("\n✅ Multi-user session isolation test PASSED!")
		t.Log("Each user has their own session and stdio process container")
	} else {
		t.Error("\n❌ Multi-user session isolation test FAILED!")
		if client1.sessionID == client2.sessionID {
			t.Error("Users are sharing the same session")
		}
		if client1Container == client2Container {
			t.Error("Users are sharing the same stdio container")
		}
	}
}

// TestSessionCleanupAfterTimeout verifies that sessions and containers are cleaned up after timeout
func TestSessionCleanupAfterTimeout(t *testing.T) {
	trace(t, "Starting session cleanup timeout test")

	// Start test database
	closeDB := startTestDB(t)
	defer closeDB()
	waitForDB(t)

	// Start mcp-front with shorter timeout for testing
	// The default is 5 minutes, but we'll set it to 10 seconds for testing
	trace(t, "Starting mcp-front with short session timeout")
	mcpCmd := startMCPFront(t, "config/config.test.json",
		"SESSION_TIMEOUT=10s",
		"SESSION_CLEANUP_INTERVAL=2s",
	)
	defer stopMCPFront(mcpCmd)
	waitForMCPFront(t)

	// Helper function to get mcp/postgres containers
	getMCPContainers := func() []string {
		cmd := exec.Command("docker", "ps", "--format", "{{.ID}}", "--filter", "ancestor=mcp/postgres")
		output, err := cmd.Output()
		if err != nil {
			t.Logf("Failed to list Docker containers: %v", err)
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

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create a client and connect
	client := NewMCPClient("http://localhost:8080")
	client.SetAuthToken("test-token")
	
	t.Log("Connecting client...")
	if err := client.Connect(); err != nil {
		t.Fatalf("Client failed to connect: %v", err)
	}
	t.Logf("Client connected with session: %s", client.sessionID)

	// Verify container was created
	containersAfterConnect := getMCPContainers()
	t.Logf("Containers after connect: %d", len(containersAfterConnect))
	
	if len(containersAfterConnect) <= len(initialContainers) {
		t.Fatal("No new container created for client")
	}

	// Send a query to ensure session is active
	_, err := client.SendMCPRequest("tools/call", map[string]interface{}{
		"name": "query",
		"arguments": map[string]interface{}{
			"sql": "SELECT 'test' as test_id",
		},
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// Close the client connection (but don't remove the session)
	client.Close()
	t.Log("Client connection closed, session should remain active")

	// Verify container is still there immediately after close
	containersAfterClose := getMCPContainers()
	t.Logf("Containers immediately after close: %d", len(containersAfterClose))
	
	if len(containersAfterClose) < len(containersAfterConnect) {
		t.Error("Container was removed immediately after close (should remain until timeout)")
	}

	// Wait for timeout + cleanup interval (10s + 2s + buffer)
	t.Log("Waiting 15 seconds for session timeout and cleanup...")
	time.Sleep(15 * time.Second)

	// Check if container was cleaned up
	containersAfterTimeout := getMCPContainers()
	t.Logf("Containers after timeout: %d", len(containersAfterTimeout))
	
	if len(containersAfterTimeout) != len(initialContainers) {
		t.Errorf("Container was not cleaned up after timeout. Expected %d containers, got %d",
			len(initialContainers), len(containersAfterTimeout))
	} else {
		t.Log("✅ Container was successfully cleaned up after session timeout")
	}
}

// TestSessionTimerReset verifies that using a session resets its timeout timer
func TestSessionTimerReset(t *testing.T) {
	trace(t, "Starting session timer reset test")

	// Start test database
	closeDB := startTestDB(t)
	defer closeDB()
	waitForDB(t)

	// Start mcp-front with shorter timeout for testing
	trace(t, "Starting mcp-front with short session timeout")
	mcpCmd := startMCPFront(t, "config/config.test.json",
		"SESSION_TIMEOUT=8s",
		"SESSION_CLEANUP_INTERVAL=2s",
	)
	defer stopMCPFront(mcpCmd)
	waitForMCPFront(t)

	// Helper function to get mcp/postgres containers
	getMCPContainers := func() []string {
		cmd := exec.Command("docker", "ps", "--format", "{{.ID}}", "--filter", "ancestor=mcp/postgres")
		output, err := cmd.Output()
		if err != nil {
			t.Logf("Failed to list Docker containers: %v", err)
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

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create a client and connect
	client := NewMCPClient("http://localhost:8080")
	client.SetAuthToken("test-token")
	
	t.Log("Connecting client...")
	if err := client.Connect(); err != nil {
		t.Fatalf("Client failed to connect: %v", err)
	}
	t.Logf("Client connected with session: %s", client.sessionID)

	// Verify container was created
	containersAfterConnect := getMCPContainers()
	if len(containersAfterConnect) <= len(initialContainers) {
		t.Fatal("No new container created for client")
	}

	// Keep session alive by sending queries every 5 seconds
	// With 8s timeout, this should keep it alive
	for i := 0; i < 3; i++ {
		t.Logf("Sending keepalive query %d/3...", i+1)
		_, err := client.SendMCPRequest("tools/call", map[string]interface{}{
			"name": "query",
			"arguments": map[string]interface{}{
				"sql": "SELECT 'keepalive' as status, NOW() as timestamp",
			},
		})
		if err != nil {
			t.Fatalf("Keepalive query %d failed: %v", i+1, err)
		}
		
		// Wait 5 seconds before next query
		if i < 2 {
			time.Sleep(5 * time.Second)
		}
	}

	// Total time elapsed: ~10 seconds (3 queries with 5s between first two)
	// With 8s timeout, session would have expired without timer reset
	t.Log("Checking if container is still active after keepalive queries...")
	
	containersAfterKeepalive := getMCPContainers()
	t.Logf("Containers after keepalive: %d", len(containersAfterKeepalive))
	
	if len(containersAfterKeepalive) < len(containersAfterConnect) {
		t.Error("Container was cleaned up despite keepalive queries (timer reset not working)")
	} else {
		t.Log("✅ Container is still active - timer reset is working")
	}

	// Now stop sending queries and close the connection
	t.Log("Stopping keepalive queries and closing connection...")
	client.Close()
	
	// Wait for timeout
	t.Log("Waiting for session timeout...")
	time.Sleep(12 * time.Second) // 8s timeout + 2s cleanup interval + buffer

	containersAfterTimeout := getMCPContainers()
	t.Logf("Containers after timeout: %d", len(containersAfterTimeout))
	
	if len(containersAfterTimeout) != len(initialContainers) {
		t.Errorf("Container was not cleaned up after timeout. Expected %d containers, got %d",
			len(initialContainers), len(containersAfterTimeout))
	} else {
		t.Log("✅ Container was successfully cleaned up after inactivity timeout")
	}
}

// TestMultiUserTimerIndependence verifies that each user's session timer is independent
func TestMultiUserTimerIndependence(t *testing.T) {
	trace(t, "Starting multi-user timer independence test")

	// Start test database
	closeDB := startTestDB(t)
	defer closeDB()
	waitForDB(t)

	// Start mcp-front with shorter timeout for testing
	trace(t, "Starting mcp-front with short session timeout")
	mcpCmd := startMCPFront(t, "config/config.test.json",
		"SESSION_TIMEOUT=10s",
		"SESSION_CLEANUP_INTERVAL=2s",
	)
	defer stopMCPFront(mcpCmd)
	waitForMCPFront(t)

	// Helper function to get mcp/postgres containers
	getMCPContainers := func() []string {
		cmd := exec.Command("docker", "ps", "--format", "{{.ID}}", "--filter", "ancestor=mcp/postgres")
		output, err := cmd.Output()
		if err != nil {
			t.Logf("Failed to list Docker containers: %v", err)
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

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create two clients
	client1 := NewMCPClient("http://localhost:8080")
	client1.SetAuthToken("test-token")
	
	client2 := NewMCPClient("http://localhost:8080")
	client2.SetAuthToken("alt-test-token")

	// Connect both clients
	t.Log("Connecting client1...")
	if err := client1.Connect(); err != nil {
		t.Fatalf("Client1 failed to connect: %v", err)
	}
	t.Logf("Client1 connected with session: %s", client1.sessionID)

	// Wait a bit before connecting client2
	time.Sleep(3 * time.Second)

	t.Log("Connecting client2...")
	if err := client2.Connect(); err != nil {
		t.Fatalf("Client2 failed to connect: %v", err)
	}
	t.Logf("Client2 connected with session: %s", client2.sessionID)

	// Verify both containers exist
	containersAfterBothConnect := getMCPContainers()
	if len(containersAfterBothConnect) != len(initialContainers)+2 {
		t.Fatalf("Expected 2 new containers, got %d", len(containersAfterBothConnect)-len(initialContainers))
	}

	// Keep client2 active while letting client1 timeout
	t.Log("Keeping client2 active while client1 becomes idle...")
	
	// Close client1's connection to make it idle
	client1.Close()
	
	// Keep client2 active with periodic queries
	go func() {
		for i := 0; i < 4; i++ {
			time.Sleep(4 * time.Second)
			_, err := client2.SendMCPRequest("tools/call", map[string]interface{}{
				"name": "query",
				"arguments": map[string]interface{}{
					"sql": "SELECT 'client2-keepalive' as status",
				},
			})
			if err != nil {
				t.Logf("Client2 keepalive query %d failed: %v", i+1, err)
			} else {
				t.Logf("Client2 keepalive query %d succeeded", i+1)
			}
		}
	}()

	// Wait for client1's timeout (10s + cleanup interval)
	t.Log("Waiting for client1 timeout while client2 stays active...")
	time.Sleep(15 * time.Second)

	// Check containers - should have only 1 now (client2's)
	containersAfterClient1Timeout := getMCPContainers()
	t.Logf("Containers after client1 timeout: %d", len(containersAfterClient1Timeout))
	
	expectedContainers := len(initialContainers) + 1 // Only client2's container
	if len(containersAfterClient1Timeout) != expectedContainers {
		t.Errorf("Expected %d containers after client1 timeout, got %d", 
			expectedContainers, len(containersAfterClient1Timeout))
	} else {
		t.Log("✅ Client1's container was cleaned up while client2's remained active")
	}

	// Clean up client2
	client2.Close()
}