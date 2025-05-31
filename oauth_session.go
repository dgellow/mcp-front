package main

import (
	"time"

	"github.com/ory/fosite"
)

// UserInfo represents Google user information
type UserInfo struct {
	Email         string `json:"email"`
	HostedDomain  string `json:"hd"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	VerifiedEmail bool   `json:"verified_email"`
}

// CustomSession extends DefaultSession with user information
type CustomSession struct {
	*fosite.DefaultSession
	UserInfo *UserInfo `json:"user_info,omitempty"`
}

// Clone implements fosite.Session
func (s *CustomSession) Clone() fosite.Session {
	return &CustomSession{
		DefaultSession: s.DefaultSession.Clone().(*fosite.DefaultSession),
		UserInfo:       s.UserInfo,
	}
}

// NewCustomSession creates a new session with user info
func NewCustomSession(userInfo *UserInfo) *CustomSession {
	return &CustomSession{
		DefaultSession: &fosite.DefaultSession{
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().Add(time.Hour),
				fosite.RefreshToken: time.Now().Add(24 * time.Hour),
			},
			Username: userInfo.Email,
			Subject:  userInfo.Email,
		},
		UserInfo: userInfo,
	}
}