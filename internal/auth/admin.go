package auth

import (
	"context"
	
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/storage"
)

// IsAdmin checks if a user is admin (either config-based or promoted)
func IsAdmin(ctx context.Context, email string, adminConfig *config.AdminConfig, store storage.Storage) bool {
	if adminConfig == nil || !adminConfig.Enabled {
		return false
	}
	
	// Check if user is a config admin (super admin)
	if IsConfigAdmin(email, adminConfig) {
		return true
	}
	
	// Check if user is a promoted admin in storage
	if store != nil {
		users, err := store.GetAllUsers(ctx)
		if err == nil {
			for _, user := range users {
				if user.Email == email && user.IsAdmin {
					return true
				}
			}
		}
	}
	
	return false
}

// IsConfigAdmin checks if an email is in the config admin list (super admins)
func IsConfigAdmin(email string, adminConfig *config.AdminConfig) bool {
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