package auth

import (
	"context"
)

type contextKey string

const (
	userKey        contextKey = "auth.user"
	serviceAuthKey contextKey = "auth.service"
)

// ServiceAuthInfo contains service authentication details
type ServiceAuthInfo struct {
	ServiceName string
	UserToken   string
}

// WithUser adds a username to the context (for basic auth)
func WithUser(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, userKey, username)
}

// GetUser retrieves the username from context (for basic auth)
func GetUser(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(userKey).(string)
	return username, ok
}

// WithServiceAuth adds service authentication info to the context
func WithServiceAuth(ctx context.Context, serviceName, userToken string) context.Context {
	return context.WithValue(ctx, serviceAuthKey, ServiceAuthInfo{
		ServiceName: serviceName,
		UserToken:   userToken,
	})
}

// GetServiceAuth retrieves service auth info from context
func GetServiceAuth(ctx context.Context) (ServiceAuthInfo, bool) {
	info, ok := ctx.Value(serviceAuthKey).(ServiceAuthInfo)
	return info, ok
}

// GetServiceName retrieves the service name from context
func GetServiceName(ctx context.Context) (string, bool) {
	info, ok := GetServiceAuth(ctx)
	if !ok {
		return "", false
	}
	return info.ServiceName, true
}
