package internal

import (
	"os"
	"strings"
)

// IsDevelopmentMode checks if we're running in development mode
// where security requirements can be relaxed for testing
func IsDevelopmentMode() bool {
	env := strings.ToLower(os.Getenv("MCP_FRONT_ENV"))
	return env == "development" || env == "dev"
}
