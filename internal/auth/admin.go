package auth

import "github.com/dgellow/mcp-front/internal/config"

// IsAdmin checks if an email is in the admin list
func IsAdmin(email string, adminConfig *config.AdminConfig) bool {
	if adminConfig == nil || !adminConfig.Enabled {
		return false
	}
	
	for _, adminEmail := range adminConfig.AdminEmails {
		if email == adminEmail {
			return true
		}
	}
	return false
}