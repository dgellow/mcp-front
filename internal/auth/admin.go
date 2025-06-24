package auth

import (
	"context"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/dgellow/mcp-front/internal/utils"
)

// IsAdmin checks if a user is admin (either config-based or promoted)
func IsAdmin(ctx context.Context, email string, adminConfig *config.AdminConfig, store storage.Storage) bool {
	if adminConfig == nil || !adminConfig.Enabled {
		return false
	}

	// Normalize the input email
	normalizedEmail := utils.NormalizeEmail(email)

	// Check if user is a config admin (super admin)
	if IsConfigAdmin(normalizedEmail, adminConfig) {
		return true
	}

	// Check if user is a promoted admin in storage
	if store != nil {
		users, err := store.GetAllUsers(ctx)
		if err == nil {
			for _, user := range users {
				if utils.NormalizeEmail(user.Email) == normalizedEmail && user.IsAdmin {
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

	// Email should already be normalized by the caller, but normalize anyway for safety
	normalizedEmail := utils.NormalizeEmail(email)

	for _, adminEmail := range adminConfig.AdminEmails {
		// Admin emails should be normalized during config load, but we normalize here too
		// to handle any legacy configs or manual edits
		if utils.NormalizeEmail(adminEmail) == normalizedEmail {
			return true
		}
	}
	return false
}
