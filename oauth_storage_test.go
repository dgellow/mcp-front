package main

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
)

func TestNewGCPIAMStorage(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GCPProject:         "test-project",
		AllowedDomains:     []string{"example.com"},
		TokenTTL:           Duration(time.Hour),
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	storage, err := NewGCPIAMStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	if storage.config != config {
		t.Error("Config not properly stored")
	}

	if storage.googleOAuth == nil {
		t.Error("Google OAuth config not initialized")
	}

	if storage.stateCache == nil {
		t.Error("State cache not initialized")
	}
}

func TestGenerateState(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	storage, err := NewGCPIAMStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	state1 := storage.GenerateState()
	state2 := storage.GenerateState()

	if state1 == state2 {
		t.Error("Generated states should be unique")
	}

	if len(state1) == 0 {
		t.Error("Generated state should not be empty")
	}
}

func TestStoreAndGetAuthorizeRequest(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	storage, err := NewGCPIAMStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	// Create a mock authorize request
	mockRequest := &fosite.AuthorizeRequest{
		Request: fosite.Request{
			ID: "test-request-id",
		},
	}

	state := "test-state"
	
	// Store the request
	storage.StoreAuthorizeRequest(state, mockRequest)

	// Retrieve the request
	retrieved, found := storage.GetAuthorizeRequest(state)
	if !found {
		t.Error("Stored request not found")
	}

	if retrieved.GetID() != mockRequest.GetID() {
		t.Error("Retrieved request ID doesn't match stored request")
	}

	// Should be deleted after retrieval (one-time use)
	_, found = storage.GetAuthorizeRequest(state)
	if found {
		t.Error("Request should be deleted after retrieval")
	}
}

func TestCreateClient(t *testing.T) {
	config := &OAuthConfig{
		Issuer:             "https://test.example.com",
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: "test-client-secret",
		GoogleRedirectURI:  "https://test.example.com/callback",
	}

	storage, err := NewGCPIAMStorage(config)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	metadata := map[string]interface{}{
		"redirect_uris": []interface{}{
			"https://client.example.com/callback",
		},
		"scope": "read write",
	}

	client, err := storage.CreateClient(context.Background(), metadata)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client.GetID() == "" {
		t.Error("Client ID should not be empty")
	}

	if len(client.Secret) == 0 {
		t.Error("Client secret should not be empty")
	}

	if len(client.GetRedirectURIs()) != 1 || client.GetRedirectURIs()[0] != "https://client.example.com/callback" {
		t.Error("Redirect URIs not properly set")
	}

	// Verify client is stored
	storedClient, err := storage.MemoryStore.GetClient(context.Background(), client.GetID())
	if err != nil {
		t.Fatalf("Failed to retrieve stored client: %v", err)
	}

	if storedClient.GetID() != client.GetID() {
		t.Error("Stored client ID doesn't match created client")
	}
}

func TestNewCustomSession(t *testing.T) {
	userInfo := &UserInfo{
		Email:         "test@example.com",
		HostedDomain:  "example.com",
		Name:          "Test User",
		Picture:       "https://example.com/picture.jpg",
		VerifiedEmail: true,
	}

	session := NewCustomSession(userInfo)

	if session.UserInfo != userInfo {
		t.Error("UserInfo not properly stored in session")
	}

	if session.DefaultSession == nil {
		t.Error("DefaultSession not initialized")
	}

	if session.DefaultSession.Username != userInfo.Email {
		t.Error("Username not set to email")
	}

	if session.DefaultSession.Subject != userInfo.Email {
		t.Error("Subject not set to email")
	}

	// Test clone
	cloned := session.Clone()
	clonedCustom, ok := cloned.(*CustomSession)
	if !ok {
		t.Error("Cloned session is not CustomSession type")
	}

	if clonedCustom.UserInfo.Email != userInfo.Email {
		t.Error("Cloned session doesn't preserve UserInfo")
	}
}