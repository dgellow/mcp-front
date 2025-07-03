package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal"
	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/ory/fosite"
)

// AuthHandlers wraps the auth.Server to provide HTTP handlers
type AuthHandlers struct {
	authServer      *auth.Server
	mcpServers      map[string]*config.MCPClientConfig
	oauthStateToken *crypto.SignedToken
}

// OAuthState stores OAuth state during service authentication flow
type OAuthState struct {
	UserInfo     *auth.UserInfo `json:"user_info"`
	ClientID     string         `json:"client_id"`
	RedirectURI  string         `json:"redirect_uri"`
	Scopes       []string       `json:"scopes"`
	State        string         `json:"state"`
	ResponseType string         `json:"response_type"`
}

// NewAuthHandlers creates new auth handlers
func NewAuthHandlers(authServer *auth.Server, mcpServers map[string]*config.MCPClientConfig) *AuthHandlers {
	return &AuthHandlers{
		authServer:      authServer,
		mcpServers:      mcpServers,
		oauthStateToken: crypto.NewSignedToken([]byte(authServer.GetConfig().EncryptionKey), 10*time.Minute),
	}
}

// WellKnownHandler serves OAuth 2.0 metadata
func (h *AuthHandlers) WellKnownHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Well-known handler called: %s %s", r.Method, r.URL.Path)

	metadata := map[string]any{
		"issuer":                 h.authServer.GetConfig().Issuer,
		"authorization_endpoint": fmt.Sprintf("%s/authorize", h.authServer.GetConfig().Issuer),
		"token_endpoint":         fmt.Sprintf("%s/token", h.authServer.GetConfig().Issuer),
		"registration_endpoint":  fmt.Sprintf("%s/register", h.authServer.GetConfig().Issuer),
		"response_types_supported": []string{
			"code",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		"code_challenge_methods_supported": []string{
			"S256",
		},
		"token_endpoint_auth_methods_supported": []string{
			"none",
			"client_secret_post",
		},
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.LogError("Failed to encode well-known metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

// AuthorizeHandler handles OAuth 2.0 authorization requests
func (h *AuthHandlers) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log.Logf("Authorize handler called: %s %s", r.Method, r.URL.Path)

	// In development mode, generate a secure state parameter if missing
	// This works around bugs in OAuth clients that don't send state
	stateParam := r.URL.Query().Get("state")
	if internal.IsDevelopmentMode() && len(stateParam) == 0 {
		generatedState := crypto.GenerateSecureToken()
		log.LogWarn("Development mode: generating state parameter '%s' for buggy client", generatedState)
		q := r.URL.Query()
		q.Set("state", generatedState)
		r.URL.RawQuery = q.Encode()
		// Also update the form values
		if r.Form == nil {
			_ = r.ParseForm()
		}
		r.Form.Set("state", generatedState)
	}

	// Parse the authorize request
	ar, err := h.authServer.GetProvider().NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.LogError("Authorize request error: %v", err)
		h.authServer.GetProvider().WriteAuthorizeError(w, ar, err)
		return
	}

	state := ar.GetState()
	h.authServer.GetStorage().StoreAuthorizeRequest(state, ar)

	authURL := h.authServer.GetAuthService().GoogleAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GoogleCallbackHandler handles the callback from Google OAuth
func (h *AuthHandlers) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.LogError("Google OAuth error: %s - %s", errMsg, errDesc)
		jsonwriter.WriteBadRequest(w, fmt.Sprintf("Authentication failed: %s", errMsg))
		return
	}

	if state == "" || code == "" {
		log.LogError("Missing state or code in callback")
		jsonwriter.WriteBadRequest(w, "Invalid callback parameters")
		return
	}

	var ar fosite.AuthorizeRequester
	var isBrowserFlow bool
	var returnURL string

	if strings.HasPrefix(state, "browser:") {
		isBrowserFlow = true
		stateToken := strings.TrimPrefix(state, "browser:")

		var browserState auth.BrowserState
		if err := h.oauthStateToken.Verify(stateToken, &browserState); err != nil {
			log.LogError("Invalid browser state: %v", err)
			jsonwriter.WriteBadRequest(w, "Invalid state parameter")
			return
		}
		returnURL = browserState.ReturnURL
	} else {
		// OAuth client flow - retrieve stored authorize request
		var found bool
		ar, found = h.authServer.GetStorage().GetAuthorizeRequest(state)
		if !found {
			log.LogError("Invalid or expired state: %s", state)
			jsonwriter.WriteBadRequest(w, "Invalid or expired authorization request")
			return
		}
	}

	// Exchange code for token with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	token, err := h.authServer.GetAuthService().ExchangeCodeForToken(ctx, code)
	if err != nil {
		log.LogError("Failed to exchange code: %v", err)
		if !isBrowserFlow && ar != nil {
			h.authServer.GetProvider().WriteAuthorizeError(w, ar, fosite.ErrServerError.WithHint("Failed to exchange authorization code"))
		} else {
			jsonwriter.WriteInternalServerError(w, "Authentication failed")
		}
		return
	}

	// Validate user
	userInfo, err := h.authServer.GetAuthService().ValidateUser(ctx, token)
	if err != nil {
		log.LogError("User validation failed: %v", err)
		if !isBrowserFlow && ar != nil {
			h.authServer.GetProvider().WriteAuthorizeError(w, ar, fosite.ErrAccessDenied.WithHint(err.Error()))
		} else {
			jsonwriter.WriteForbidden(w, "Access denied")
		}
		return
	}

	log.Logf("User authenticated: %s", userInfo.Email)

	// Store user in database
	if err := h.authServer.GetStorage().UpsertUser(ctx, userInfo.Email); err != nil {
		log.LogWarnWithFields("auth", "Failed to track user", map[string]any{
			"email": userInfo.Email,
			"error": err.Error(),
		})
	}

	if isBrowserFlow {
		// Browser SSO flow - set encrypted session cookie
		sessionData := auth.SessionData{
			Email:   userInfo.Email,
			Expires: time.Now().Add(h.authServer.GetConfig().SessionDuration),
		}

		// Marshal session data to JSON
		jsonData, err := json.Marshal(sessionData)
		if err != nil {
			log.LogError("Failed to marshal session data: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create session")
			return
		}

		// Encrypt session data
		encryptedData, err := h.authServer.GetSessionEncryptor().Encrypt(string(jsonData))
		if err != nil {
			log.LogError("Failed to encrypt session: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create session")
			return
		}

		// Set secure session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "mcp_session",
			Value:    encryptedData,
			Path:     "/",
			HttpOnly: true,
			Secure:   !internal.IsDevelopmentMode(),
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(h.authServer.GetConfig().SessionDuration.Seconds()),
		})

		log.LogInfoWithFields("auth", "Browser SSO session created", map[string]any{
			"user":      userInfo.Email,
			"duration":  h.authServer.GetConfig().SessionDuration,
			"returnURL": returnURL,
		})

		// Redirect to return URL
		http.Redirect(w, r, returnURL, http.StatusFound)
		return
	}

	// OAuth client flow - check if any services need OAuth
	needsServiceAuth := false
	for _, serverConfig := range h.mcpServers {
		if serverConfig.RequiresUserToken &&
			serverConfig.UserAuthentication != nil &&
			serverConfig.UserAuthentication.Type == config.UserAuthTypeOAuth {
			needsServiceAuth = true
			break
		}
	}

	if needsServiceAuth {
		stateData, err := h.signOAuthState(ar, userInfo)
		if err != nil {
			log.LogError("Failed to sign OAuth state: %v", err)
			h.authServer.GetProvider().WriteAuthorizeError(w, ar, fosite.ErrServerError.WithHint("Failed to prepare service authentication"))
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/oauth/services?state=%s", url.QueryEscape(stateData)), http.StatusFound)
		return
	}

	session := &auth.Session{
		DefaultSession: &fosite.DefaultSession{
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().Add(h.authServer.GetConfig().TokenTTL),
				fosite.RefreshToken: time.Now().Add(h.authServer.GetConfig().TokenTTL * 2),
			},
		},
		UserInfo: userInfo,
	}

	// Accept the authorization request
	response, err := h.authServer.GetProvider().NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.LogError("Authorize response error: %v", err)
		h.authServer.GetProvider().WriteAuthorizeError(w, ar, err)
		return
	}

	h.authServer.GetProvider().WriteAuthorizeResponse(w, ar, response)
}

// TokenHandler handles OAuth 2.0 token requests
//
// TODO: feels messy, need to see if we can simplify that whole logic
func (h *AuthHandlers) TokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Token handler called: %s %s", r.Method, r.URL.Path)
	ctx := r.Context()

	// Create session for the token exchange
	// Note: We create our custom Session type here, and fosite will populate it
	// with the session data from the authorization code during NewAccessRequest
	session := &auth.Session{DefaultSession: &fosite.DefaultSession{}}

	// Handle token request - this retrieves the session from the authorization code
	accessRequest, err := h.authServer.GetProvider().NewAccessRequest(ctx, r, session)
	if err != nil {
		log.LogError("Access request error: %v", err)
		h.authServer.GetProvider().WriteAccessError(w, accessRequest, err)
		return
	}

	// At this point, accessRequest.GetSession() contains the session data from
	// the authorization phase (including our custom UserInfo). Fosite handles
	// the session propagation internally when creating the access token.

	// Generate tokens
	response, err := h.authServer.GetProvider().NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.LogError("Access response error: %v", err)
		h.authServer.GetProvider().WriteAccessError(w, accessRequest, err)
		return
	}

	h.authServer.GetProvider().WriteAccessResponse(w, accessRequest, response)
}

// buildClientRegistrationResponse creates the registration response for a client
func (h *AuthHandlers) buildClientRegistrationResponse(client *fosite.DefaultClient, tokenEndpointAuthMethod string, clientSecret string) map[string]any {
	response := map[string]any{
		"client_id":                  client.GetID(),
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              client.GetRedirectURIs(),
		"grant_types":                client.GetGrantTypes(),
		"response_types":             client.GetResponseTypes(),
		"scope":                      strings.Join(client.GetScopes(), " "), // Space-separated string
		"token_endpoint_auth_method": tokenEndpointAuthMethod,
	}

	// Include client_secret only for confidential clients
	if clientSecret != "" {
		response["client_secret"] = clientSecret
	}

	return response
}

// RegisterHandler handles dynamic client registration (RFC 7591)
func (h *AuthHandlers) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Register handler called: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	// Parse client metadata
	var metadata map[string]any
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		jsonwriter.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Parse client request
	redirectURIs, scopes, err := h.authServer.GetAuthService().ParseClientRequest(metadata)
	if err != nil {
		log.LogError("Client request parsing error: %v", err)
		jsonwriter.WriteBadRequest(w, err.Error())
		return
	}

	// Check if client requests client_secret_post authentication
	tokenEndpointAuthMethod := "none"
	var client *fosite.DefaultClient
	var plaintextSecret string
	clientID := crypto.GenerateSecureToken()

	if authMethod, ok := metadata["token_endpoint_auth_method"].(string); ok && authMethod == "client_secret_post" {
		// Create confidential client with a secret
		plaintextSecret = crypto.GenerateSecureToken()
		hashedSecret, err := crypto.HashClientSecret(plaintextSecret)
		if err != nil {
			log.LogError("Failed to hash client secret: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create client")
			return
		}
		client = h.authServer.GetStorage().CreateConfidentialClient(clientID, hashedSecret, redirectURIs, scopes, h.authServer.GetConfig().Issuer)
		tokenEndpointAuthMethod = "client_secret_post"
		log.Logf("Creating confidential client %s with client_secret_post authentication", clientID)
	} else {
		// Create public client (no secret)
		client = h.authServer.GetStorage().CreateClient(clientID, redirectURIs, scopes, h.authServer.GetConfig().Issuer)
		log.Logf("Creating public client %s with no authentication", clientID)
	}

	response := h.buildClientRegistrationResponse(client, tokenEndpointAuthMethod, plaintextSecret)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.LogError("Failed to encode registration response: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to create client")
	}
}

// signOAuthState signs OAuth state for secure storage
func (h *AuthHandlers) signOAuthState(ar fosite.AuthorizeRequester, userInfo *auth.UserInfo) (string, error) {
	state := OAuthState{
		UserInfo:     userInfo,
		ClientID:     ar.GetClient().GetID(),
		RedirectURI:  ar.GetRedirectURI().String(),
		Scopes:       ar.GetRequestedScopes(),
		State:        ar.GetState(),
		ResponseType: ar.GetResponseTypes()[0],
	}

	return h.oauthStateToken.Sign(state)
}

// verifyOAuthState verifies and validates OAuth state
func (h *AuthHandlers) verifyOAuthState(signedState string) (*OAuthState, error) {
	var state OAuthState
	if err := h.oauthStateToken.Verify(signedState, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ServiceSelectionHandler shows the interstitial page for selecting services to connect
func (h *AuthHandlers) ServiceSelectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	signedState := r.URL.Query().Get("state")
	if signedState == "" {
		jsonwriter.WriteBadRequest(w, "Missing state parameter")
		return
	}

	oauthState, err := h.verifyOAuthState(signedState)
	if err != nil {
		log.LogError("Failed to verify OAuth state: %v", err)
		jsonwriter.WriteBadRequest(w, "Invalid or expired session")
		return
	}

	userEmail := oauthState.UserInfo.Email

	// Prepare service list
	var services []ServiceSelectionData
	for name, serverConfig := range h.mcpServers {
		if serverConfig.RequiresUserToken &&
			serverConfig.UserAuthentication != nil &&
			serverConfig.UserAuthentication.Type == config.UserAuthTypeOAuth {

			// Check if user already has valid token
			token, _ := h.authServer.GetStorage().GetUserToken(r.Context(), userEmail, name)
			status := "not_connected"
			if token != nil {
				status = "connected"
			}

			displayName := name
			if serverConfig.UserAuthentication.DisplayName != "" {
				displayName = serverConfig.UserAuthentication.DisplayName
			}

			// Check for error from callback
			if r.URL.Query().Get("error") != "" && r.URL.Query().Get("service") == name {
				status = "error"
			}

			services = append(services, ServiceSelectionData{
				Name:        name,
				DisplayName: displayName,
				Status:      status,
				ErrorMsg:    r.URL.Query().Get("error_description"),
			})
		}
	}

	// Prepare template data
	returnURL := fmt.Sprintf("/oauth/services?state=%s", url.QueryEscape(signedState))
	pageData := ServicesPageData{
		Services:  services,
		State:     url.QueryEscape(signedState),
		ReturnURL: url.QueryEscape(returnURL),
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := servicesPageTemplate.Execute(w, pageData); err != nil {
		log.LogError("Failed to render services page: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to render page")
	}
}

// CompleteOAuthHandler completes the original OAuth flow after service selection
func (h *AuthHandlers) CompleteOAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	signedState := r.URL.Query().Get("state")
	if signedState == "" {
		jsonwriter.WriteBadRequest(w, "Missing state parameter")
		return
	}

	oauthState, err := h.verifyOAuthState(signedState)
	if err != nil {
		log.LogError("Failed to verify OAuth state: %v", err)
		jsonwriter.WriteBadRequest(w, "Invalid or expired session")
		return
	}

	// Recreate the authorize request
	ctx := r.Context()
	client, err := h.authServer.GetStorage().GetClient(ctx, oauthState.ClientID)
	if err != nil {
		log.LogError("Failed to get client: %v", err)
		jsonwriter.WriteInternalServerError(w, "Client not found")
		return
	}

	// Create a new authorize request with the stored parameters
	ar := &fosite.AuthorizeRequest{
		ResponseTypes:        fosite.Arguments{oauthState.ResponseType},
		RedirectURI:          &url.URL{},
		State:                oauthState.State,
		HandledResponseTypes: fosite.Arguments{},
		Request: fosite.Request{
			ID:             crypto.GenerateSecureToken(),
			RequestedAt:    time.Now(),
			Client:         client,
			RequestedScope: oauthState.Scopes,
			GrantedScope:   oauthState.Scopes,
			Session:        &auth.Session{DefaultSession: &fosite.DefaultSession{}},
		},
	}

	redirectURI, err := url.Parse(oauthState.RedirectURI)
	if err != nil {
		log.LogError("Failed to parse redirect URI: %v", err)
		jsonwriter.WriteInternalServerError(w, "Invalid redirect URI")
		return
	}
	ar.RedirectURI = redirectURI

	// Create session with user info
	session := &auth.Session{
		DefaultSession: &fosite.DefaultSession{
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().Add(h.authServer.GetConfig().TokenTTL),
				fosite.RefreshToken: time.Now().Add(h.authServer.GetConfig().TokenTTL * 2),
			},
		},
		UserInfo: oauthState.UserInfo,
	}
	ar.SetSession(session)

	// Accept the authorization request
	response, err := h.authServer.GetProvider().NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.LogError("Authorize response error: %v", err)
		h.authServer.GetProvider().WriteAuthorizeError(w, ar, err)
		return
	}

	// Write the response (redirects to Claude)
	h.authServer.GetProvider().WriteAuthorizeResponse(w, ar, response)
}
