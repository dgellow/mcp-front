package utils

import "strings"

// NormalizeEmail normalizes an email address for consistent comparison
// by converting to lowercase and trimming whitespace
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
